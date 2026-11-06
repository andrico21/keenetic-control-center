//! Permission, account and API-key security-boundary tests.

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::{
        error::Error,
        fmt,
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    use std::fs;

    use kcc_app::{
        accounts::{
            ARGON2_ITERATIONS, ARGON2_LANES, ARGON2_MEMORY_KIB, AccountChange, AccountError,
            AccountStore, Authentication, Clock, NewAccount, password_params,
        },
        api_keys::{api_key_entries, create_api_key, expose_created_key},
        permissions::{Permission, Role, ToolSpec, built_in_roles, rbac_config},
        persist::StateStore,
        secrets::MasterKey,
    };
    use rmcp_server_kit::rbac::{RbacDecision, RbacPolicy};
    use secrecy::SecretString;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

    #[derive(Debug, Default)]
    struct MockClock {
        now: AtomicU64,
    }

    impl MockClock {
        fn advance(&self, duration: Duration) {
            let _: u64 = self.now.fetch_add(duration.as_secs(), Ordering::SeqCst);
        }
    }

    impl Clock for MockClock {
        fn unix_seconds(&self) -> u64 {
            self.now.load(Ordering::SeqCst)
        }
    }

    fn store() -> Result<(TempDir, StateStore), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        Ok((temp, state))
    }

    #[test]
    fn role_permissions_generate_tool_allowlists_and_router_globs() {
        let mut roles = Vec::from(built_in_roles());
        roles.push(Role::new(
            "branch-reader".to_owned(),
            [Permission::Read],
            vec!["branch-*".to_owned()],
        ));
        let tools = [
            ToolSpec::new("router_show".to_owned(), Permission::Read, None),
            ToolSpec::new("router_set".to_owned(), Permission::Write, None),
            ToolSpec::new("router_save".to_owned(), Permission::Save, None),
            ToolSpec::new("router_reset".to_owned(), Permission::Destructive, None),
        ];

        let policy = RbacPolicy::new(&rbac_config(&roles, &tools));

        assert_eq!(
            policy.check("viewer", "router_show", "home"),
            RbacDecision::Allow,
            "viewer may read"
        );
        assert_eq!(
            policy.check("viewer", "router_set", "home"),
            RbacDecision::Deny,
            "viewer may not write"
        );
        assert_eq!(
            policy.check("operator", "router_save", "home"),
            RbacDecision::Allow,
            "operator may save"
        );
        assert_eq!(
            policy.check("operator", "router_reset", "home"),
            RbacDecision::Deny,
            "operator lacks destructive permission"
        );
        assert_eq!(
            policy.check("admin", "router_reset", "home"),
            RbacDecision::Allow,
            "admin has every permission"
        );
        assert_eq!(
            policy.check("branch-reader", "router_show", "branch-east"),
            RbacDecision::Allow,
            "router-name glob matches"
        );
        assert_eq!(
            policy.check("branch-reader", "router_show", "home"),
            RbacDecision::Deny,
            "router-name glob rejects outside scope"
        );
    }

    #[test]
    fn password_hashing_uses_exact_owasp_argon2id_parameters() -> TestResult {
        let params = password_params()?;

        assert_eq!(params.m_cost(), ARGON2_MEMORY_KIB, "memory cost");
        assert_eq!(params.t_cost(), ARGON2_ITERATIONS, "iteration cost");
        assert_eq!(params.p_cost(), ARGON2_LANES, "parallelism cost");
        Ok(())
    }

    #[test]
    fn fifth_failure_locks_and_window_expiry_auto_unlocks() -> TestResult {
        let (_temp, state) = store()?;
        let clock = Arc::new(MockClock::default());
        let injected: Arc<dyn Clock> = Arc::<MockClock>::clone(&clock);
        let accounts = AccountStore::new(
            state,
            MasterKey::generate()?,
            Duration::from_secs(60),
            injected,
        );
        accounts.create(NewAccount::new(
            "alice".to_owned(),
            SecretString::from("correct horse battery staple"),
            "admin".to_owned(),
        ))?;

        for attempt in 1_u32..=5 {
            let outcome = accounts.authenticate("alice", &SecretString::from("wrong password"))?;
            if attempt < 5 {
                assert_eq!(outcome, Authentication::Invalid, "attempt {attempt}");
            } else {
                assert_eq!(
                    outcome,
                    Authentication::Locked { until: 60 },
                    "fifth attempt"
                );
            }
        }
        clock.advance(Duration::from_secs(60));
        let outcome =
            accounts.authenticate("alice", &SecretString::from("correct horse battery staple"))?;

        assert_eq!(
            outcome,
            Authentication::Authenticated {
                role: "admin".to_owned(),
                locale: "en".to_owned(),
            },
            "expired lockout resets and valid password authenticates"
        );
        Ok(())
    }

    #[test]
    fn api_key_file_never_contains_plaintext() -> TestResult {
        let (_temp, state) = store()?;

        let created = create_api_key(&state, "automation".to_owned(), "operator".to_owned(), 7)?;
        let plaintext = expose_created_key(&created);
        let raw = fs::read_to_string(state.dir().join("api_keys.json"))?;
        let entries = api_key_entries(&state)?;

        assert!(
            !raw.contains(plaintext),
            "plaintext bearer token must not be persisted"
        );
        assert_eq!(entries.len(), 1, "one kit auth entry is produced");
        let entry = entries.first().ok_or(MissingEntry)?;
        assert_eq!(entry.name, "automation", "entry principal");
        assert_eq!(entry.role, "operator", "entry role");
        assert_ne!(entry.hash, plaintext, "entry stores a hash, not plaintext");
        Ok(())
    }

    #[derive(Debug)]
    struct MissingEntry;

    impl fmt::Display for MissingEntry {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("API key entry missing")
        }
    }

    impl Error for MissingEntry {}

    #[test]
    fn administration_keeps_one_enabled_admin_and_the_flag_stays_schema_compatible() -> TestResult {
        let (_temp, state) = store()?;
        let users_file = state.dir().join("users.json");
        let accounts = AccountStore::new(
            state,
            MasterKey::generate()?,
            Duration::from_secs(60),
            Arc::new(MockClock::default()),
        );
        accounts.create(NewAccount::new(
            "alice".to_owned(),
            SecretString::from("correct horse battery staple"),
            "admin".to_owned(),
        ))?;
        assert!(
            !fs::read_to_string(&users_file)?.contains("must_change_password"),
            "a cleared flag is not written, so older readers still accept the file"
        );

        for change in [
            AccountChange::Disabled(true),
            AccountChange::Role("viewer".to_owned()),
            AccountChange::Delete,
        ] {
            let refused = accounts.administer("alice", &change);
            assert!(
                matches!(refused, Err(AccountError::LastAdmin)),
                "{change:?}: {refused:?}"
            );
        }
        accounts.create(
            NewAccount::new(
                "bob".to_owned(),
                SecretString::from("another long passphrase"),
                "admin".to_owned(),
            )
            .with_must_change_password(true),
        )?;
        let before = accounts.administer("alice", &AccountChange::Disabled(true))?;
        assert_eq!(
            before.map(|summary| summary.disabled),
            Some(false),
            "a second enabled admin allows it"
        );
        assert!(
            matches!(
                accounts.administer("bob", &AccountChange::Delete),
                Err(AccountError::LastAdmin)
            ),
            "bob is now the last enabled admin"
        );
        assert_eq!(
            accounts.administer("nobody", &AccountChange::Unlock)?,
            None,
            "missing account"
        );

        let flagged = |name: &str| -> Result<bool, Box<dyn Error>> {
            Ok(accounts
                .list()?
                .into_iter()
                .any(|summary| summary.username == name && summary.must_change_password))
        };
        assert!(flagged("bob")?, "created with the flag");
        let changed = accounts.change_password(
            "bob",
            &SecretString::from("another long passphrase"),
            &SecretString::from("a brand new passphrase"),
        )?;
        assert!(
            matches!(
                changed,
                Authentication::Authenticated { role: _, locale: _ }
            ),
            "{changed:?}"
        );
        assert!(!flagged("bob")?, "a password change clears the flag");
        Ok(())
    }
}
