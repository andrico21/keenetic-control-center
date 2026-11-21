//! API-key names and expiry: the shared name rule, the optional `expires_at` field of
//! `api_keys.json` and its conversion to the MCP transport's key entries.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    use core::error::Error;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use kcc_app::{
        api_keys::{
            ApiKeyError, ApiKeysDocument, MAX_KEY_LIFETIME_SECS, api_key_entries, create_api_key,
            expires_after, expose_created_key, is_valid_key_name,
        },
        permissions::{Permission, Role},
        persist::StateStore,
    };
    use rmcp_server_kit::auth::verify_bearer_token;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

    /// Creation time of the keys of this suite.
    const NOW: u64 = 1_800_000_000;

    fn admin() -> Role {
        Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
    }

    fn store() -> Result<(TempDir, StateStore), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let store = StateStore::open(directory.path())?;
        Ok((directory, store))
    }

    fn create(
        store: &StateStore,
        name: &str,
        expires_at: Option<u64>,
    ) -> Result<String, ApiKeyError> {
        let created = create_api_key(
            store,
            &admin(),
            name.to_owned(),
            "viewer".to_owned(),
            NOW,
            expires_at,
        )?;
        Ok(expose_created_key(&created).to_owned())
    }

    /// Todo 24: a key with and a key without an expiry survive a write and a read; only
    /// the expiring one has the field on disk, and the transport entry carries it as
    /// RFC 3339.
    #[test]
    fn keys_round_trip_with_and_without_an_expiry() -> TestResult {
        let (_directory, store) = store()?;
        drop(create(&store, "forever", None)?);
        drop(create(&store, "brief", Some(NOW + 3_600))?);

        let raw = fs::read_to_string(store.dir().join("api_keys.json"))?;
        assert_eq!(raw.matches("\"expires_at\"").count(), 1, "{raw}");
        let keys = store.read::<ApiKeysDocument>()?.ok_or("no keys")?.keys;
        let expiry = |name: &str| {
            keys.iter()
                .find(|key| key.name == name)
                .map(|key| key.expires_at)
        };
        assert_eq!(expiry("forever"), Some(None), "no expiry");
        assert_eq!(expiry("brief"), Some(Some(NOW + 3_600)), "stored expiry");

        let entries = api_key_entries(&store)?;
        let entry = |name: &str| entries.iter().find(|entry| entry.name == name);
        assert!(
            entry("forever").is_some_and(|found| found.expires_at.is_none()),
            "no expiry in the transport"
        );
        assert_eq!(
            entry("brief")
                .and_then(|found| found.expires_at)
                .map(|at| at.as_datetime().timestamp()),
            Some(1_800_003_600),
            "the transport expiry"
        );
        Ok(())
    }

    /// Todo 24: an `api_keys.json` written before keys could expire still loads, and its
    /// keys never expire.
    #[test]
    fn a_file_without_the_expiry_field_still_loads() -> TestResult {
        let (_directory, store) = store()?;
        let hash = ["hash", "placeholder"].join("-");
        fs::write(
            store.dir().join("api_keys.json"),
            format!(
                r#"{{"schema":1,"keys":[{{"name":"old","hash":"{hash}","role":"viewer","created_at":1,"last_used_at":null}}]}}"#
            ),
        )?;

        let keys = store.read::<ApiKeysDocument>()?.ok_or("no keys")?.keys;
        assert_eq!(keys.len(), 1, "one key");
        assert!(keys.iter().all(|key| key.expires_at.is_none()), "no expiry");
        assert!(
            api_key_entries(&store)?
                .iter()
                .all(|entry| entry.expires_at.is_none()),
            "no transport expiry"
        );
        Ok(())
    }

    /// Todo 24: every surface refuses a name outside 1 to 64 of `a-z0-9._-`, so no key
    /// takes an identity namespace such as `oauth:`; nothing is stored.
    #[test]
    fn names_outside_the_rule_are_refused() -> TestResult {
        let (_directory, store) = store()?;
        let long = "k".repeat(65);
        for name in [
            "oauth:alice",
            "",
            "Alice",
            "a b",
            "caf\u{e9}",
            long.as_str(),
        ] {
            assert!(!is_valid_key_name(name), "{name:?}");
            assert!(
                matches!(create(&store, name, None), Err(ApiKeyError::InvalidName)),
                "{name:?}"
            );
        }
        assert!(store.read::<ApiKeysDocument>()?.is_none(), "nothing stored");
        let longest = "k".repeat(64);
        for name in ["ci", "ci-bot_2.prod", longest.as_str()] {
            assert!(is_valid_key_name(name), "{name}");
        }
        drop(create(&store, &longest, None)?);
        Ok(())
    }

    /// Todo 24: an expiry at or before the creation time, or beyond the longest key
    /// lifetime, is refused at creation; nothing is stored.
    #[test]
    fn an_expiry_not_after_creation_or_too_far_ahead_is_refused() -> TestResult {
        let (_directory, store) = store()?;
        for expires_at in [0, NOW - 1, NOW, NOW + MAX_KEY_LIFETIME_SECS + 1, u64::MAX] {
            assert!(
                matches!(
                    create(&store, "ci", Some(expires_at)),
                    Err(ApiKeyError::InvalidExpiry)
                ),
                "{expires_at}"
            );
        }
        assert!(store.read::<ApiKeysDocument>()?.is_none(), "nothing stored");
        drop(create(&store, "ci", Some(NOW + MAX_KEY_LIFETIME_SECS))?);
        Ok(())
    }

    /// Todo 24: a lifetime is a positive humantime duration; anything else is refused.
    #[test]
    fn a_lifetime_is_a_positive_humantime_duration() -> TestResult {
        assert_eq!(expires_after(NOW, "1h")?, NOW + 3_600, "one hour");
        assert_eq!(expires_after(NOW, "7d")?, NOW + 7 * 86_400, "seven days");
        for raw in ["", "0s", "-1h", "soon", "1h-", "99999999999999999999y"] {
            assert!(
                matches!(expires_after(NOW, raw), Err(ApiKeyError::InvalidExpiry)),
                "{raw:?}"
            );
        }
        Ok(())
    }

    /// Todo 24: the transport refuses a key whose stored expiry has passed and still
    /// accepts a key without one.
    #[test]
    fn an_expired_key_never_authenticates() -> TestResult {
        let (_directory, store) = store()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let created = |name: &str, expires_at| {
            create_api_key(
                &store,
                &admin(),
                name.to_owned(),
                "viewer".to_owned(),
                now,
                expires_at,
            )
            .map(|created| expose_created_key(&created).to_owned())
        };
        let kept = created("kept", None)?;
        let lapsed = created("lapsed", Some(now.saturating_add(3_600)))?;
        store.update(|document: &mut ApiKeysDocument| {
            for key in document.keys.iter_mut().filter(|key| key.name == "lapsed") {
                key.expires_at = Some(now.saturating_sub(60));
            }
        })?;

        let entries = api_key_entries(&store)?;
        assert_eq!(
            verify_bearer_token(&kept, &entries).map(|identity| identity.name),
            Some("kept".to_owned()),
            "the key without expiry"
        );
        assert!(
            verify_bearer_token(&lapsed, &entries).is_none(),
            "the expired key authenticated"
        );
        Ok(())
    }
}
