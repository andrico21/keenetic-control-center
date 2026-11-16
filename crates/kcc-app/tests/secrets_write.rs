//! Secret writes through the real workflow, HTTP client and fake router.
extern crate alloc;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions define secret transport contracts"
)]
mod tests {
    use alloc::sync::Arc;
    use core::error::Error;
    use std::{
        io::{self, Write},
        sync::Mutex,
    };

    use kcc_app::{
        audit::{AUDIT_FILE_NAME, Actor, ActorKind, AuditLog},
        backups::BackupStore,
        permissions::{Permission, Role},
        persist::StateStore,
        registry::{ManagedRouterProfile, RouterRegistry},
        secrets::MasterKey,
        settings::OutboundConfig,
        workflow::{
            ChangeSet, ChangeWorkflow, CliChangeRequest, CliCommand, PresencePredicate,
            VerificationSpec,
        },
    };
    use kcc_catalog::Catalog;
    use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, model::Profile};
    use secrecy::SecretString;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::fs;
    use tracing::{Level, subscriber::set_default};
    use url::Url;

    /// Shared byte sink for the actual TRACE subscriber.
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .map_err(|_error| io::Error::other("capture poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Password hashing and quoted PSK storage occur without plaintext in observable outputs.
    // NOT cancel-safe: creates isolated fixture state and applies mutations.
    #[tokio::test]
    async fn secret_cli_writes_are_redacted_end_to_end() -> Result<(), Box<dyn Error>> {
        let capture = Capture(Arc::new(Mutex::new(Vec::new())));
        let sink = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        let _subscriber = set_default(subscriber);
        let directory = TempDir::new()?;
        let (state, catalog, mut changes, handle) = fixture(&directory).await?;
        let secret = "a secret with \"quote\" and \\ slash";
        let validated = catalog
            .validate_secret(
                "user password plain",
                "password",
                SecretString::from(secret.to_owned()),
            )
            .map_err(|_issues| "password fixture invalid")?;
        let command =
            CliCommand::from_template(validated, "user guest password plain {/password}")?;
        let request = CliChangeRequest::new(
            vec![command],
            vec![VerificationSpec::presence(
                vec!["show".to_owned(), "rc".to_owned(), "user".to_owned()],
                "/0/password/md5".to_owned(),
                PresencePredicate::LengthRange {
                    minimum: 32,
                    maximum: 32,
                },
            )],
            Permission::Write,
            json!({"detail":secret}),
        );
        let result = changes.apply_cli(request).await?;
        assert!(result.unsaved, "ordinary writes stay unsaved");
        assert!(
            !format!("{result:?}").contains(secret),
            "result must be redacted"
        );
        assert!(
            handle.running_config_text().contains("password md5"),
            "fake must store a hash"
        );
        assert!(
            !handle.running_config_text().contains(secret),
            "fake must discard plaintext"
        );
        let psk = catalog
            .validate_secret(
                "interface authentication wpa-psk",
                "psk",
                SecretString::from(secret.to_owned()),
            )
            .map_err(|_issues| "PSK fixture invalid")?;
        let wifi_command = CliCommand::from_template(
            psk,
            "interface WifiMaster0/AccessPoint0 authentication wpa-psk {/psk}",
        )?;
        let wifi_result = changes
            .apply_cli(CliChangeRequest::new(
                vec![wifi_command],
                Vec::new(),
                Permission::Write,
                json!({"detail":secret}),
            ))
            .await?;
        assert!(
            handle.running_config_text().contains("wpa-psk ns3"),
            "fake must encode the PSK"
        );
        assert!(
            !format!("{wifi_result:?}").contains(secret),
            "Wi-Fi result must be redacted"
        );
        forced_failure(&catalog, &mut changes, secret).await?;
        refuses_controls(&catalog, &handle);
        let audit = fs::read(state.dir().join(AUDIT_FILE_NAME)).await?;
        assert!(
            !String::from_utf8(audit)?.contains(secret),
            "audit must not retain plaintext"
        );
        assert!(
            !format!("{:?}", handle.request_log()).contains(secret),
            "request log must not retain plaintext"
        );
        let trace = capture
            .0
            .lock()
            .map_err(|_error| "capture poisoned")?
            .clone();
        assert!(
            !String::from_utf8(trace)?.contains(secret),
            "TRACE must not retain plaintext"
        );
        drop(changes);
        handle.shutdown().await?;
        Ok(())
    }

    /// Creates the same real workflow services used by the existing workflow suite.
    // NOT cancel-safe: creates isolated fixture state.
    async fn fixture(
        directory: &TempDir,
    ) -> Result<(StateStore, Catalog, ChangeSet, Handle), Box<dyn Error>> {
        let (address, handle) = FakeRouter::builder(Profile::default())
            .faults(FaultInjection::default().fail_parse_matching("user failcase password", 1))
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let password_file =
            kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
        let role = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        registry
            .create(
                &role,
                ManagedRouterProfile::new(
                    "router".to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    "admin".to_owned(),
                    password_file,
                ),
            )
            .await?;
        let backups = Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([7_u8; 32]),
        ));
        let workflow = ChangeWorkflow::new(
            state.clone(),
            Arc::clone(&registry),
            backups,
            AuditLog::spawn(&state)?,
        );
        let catalog = Catalog::for_router(&registry.poll_info("router").await?)?;
        let changes = workflow
            .begin(
                "router",
                Actor::new(ActorKind::Cli, "test".to_owned()),
                &role,
                false,
            )
            .await?;
        Ok((state, catalog, changes, handle))
    }

    /// Invalid secret input is rejected before reaching the router.
    fn refuses_controls(catalog: &Catalog, handle: &Handle) {
        let before = handle.request_count();
        let invalid = catalog.validate_secret(
            "user password plain",
            "password",
            SecretString::from("bad\nsecret".to_owned()),
        );
        assert!(invalid.is_err(), "control character must be refused");
        assert_eq!(
            before,
            handle.request_count(),
            "invalid input must not contact router"
        );
    }

    /// Forces a real parser failure and checks its public error boundary.
    // NOT cancel-safe: sends a router command.
    async fn forced_failure(
        catalog: &Catalog,
        changes: &mut ChangeSet,
        secret: &str,
    ) -> Result<(), Box<dyn Error>> {
        let failed = catalog
            .validate_secret(
                "user password plain",
                "password",
                SecretString::from(secret.to_owned()),
            )
            .map_err(|_issues| "failure fixture invalid")?;
        let failed_command =
            CliCommand::from_template(failed, "user failcase password plain {/password}")?;
        let failure = changes
            .apply_cli(CliChangeRequest::new(
                vec![failed_command],
                Vec::new(),
                Permission::Write,
                json!({}),
            ))
            .await;
        match failure {
            Err(error) => assert!(
                !format!("{error} {error:?}").contains(secret),
                "failure must be redacted"
            ),
            Ok(_) => return Err("forced parser failure must fail".into()),
        }
        Ok(())
    }
}
