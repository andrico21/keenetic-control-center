//! Factory-setup password transition through the leased workflow.
extern crate alloc;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions define the protected bootstrap contract"
)]
mod tests {
    use alloc::sync::Arc;
    use core::error::Error;
    use std::process;

    use kcc_app::{
        audit::{Actor, ActorKind, AuditLog, verify_chain},
        backups::BackupStore,
        credentials::{CredentialKind, CredentialStore},
        permissions::{Permission, Role},
        persist::StateStore,
        registry::{ManagedRouterProfile, RouterRegistry},
        secrets::MasterKey,
        settings::OutboundConfig,
        workflow::{ChangeWorkflow, CliCommand, ReplayOutcome, ReplayPolicy},
    };
    use kcc_catalog::Catalog;
    use kcc_rci::auth::Credentials;
    use kcc_testkit::{FakeRouter, model::Profile};
    use secrecy::{ExposeSecret as _, SecretString};
    use tempfile::TempDir;
    use tokio::fs;
    use url::Url;

    /// First-password replay survives loss of passwordless access and seals the new password:
    /// the profile's external plaintext file stays as it was and the profile points at the
    /// sealed record afterwards.
    // NOT cancel-safe: performs isolated configuration and credential writes.
    #[tokio::test]
    async fn bootstrap_transitions_the_leased_client_and_stored_password()
    -> Result<(), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let (address, handle) = FakeRouter::builder(Profile::default())
            .user("admin", "", ["cli", "http"])
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let password_file = kcc_testkit::write_secret_file(directory.path(), "password", "")?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let mut outbound = OutboundConfig::default();
        outbound.allow_loopback = true;
        let credentials = Arc::new(CredentialStore::new(
            state.clone(),
            MasterKey::from_bytes([9_u8; 32]),
        ));
        let registry = Arc::new(
            RouterRegistry::new(state.clone(), &[], &outbound)?
                .with_credentials(Arc::clone(&credentials)),
        );
        let role = Role::new("admin".to_owned(), Permission::ALL, Vec::new());
        registry
            .create(
                &role,
                ManagedRouterProfile::new(
                    "router".to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    "admin".to_owned(),
                    password_file.clone(),
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
            Arc::clone(&backups),
            AuditLog::spawn(&state)?,
        );
        let mut changes = workflow
            .begin_migration(
                "router",
                Actor::new(ActorKind::Cli, "operator".to_owned()),
                &role,
            )
            .await?;
        let client = changes.client();
        let catalog = Catalog::for_router(&client.detect().await?)?;
        let secret = format!("new-primary-{}", process::id());
        let password = secret.as_str();
        let validated = catalog
            .validate_secret(
                "user password plain",
                "password",
                SecretString::from(password.to_owned()),
            )
            .map_err(|_issues| "invalid password fixture")?;
        let command =
            CliCommand::from_template(validated, "user admin password plain {/password}")?;

        let result = changes
            .replay(&[command], ReplayPolicy::StopOnError)
            .await?;
        changes
            .reconnect(
                client.router_url().clone(),
                Some(Credentials::new(
                    "admin".to_owned(),
                    SecretString::from(password.to_owned()),
                )),
            )
            .await?;

        assert_eq!(result.outcomes, vec![ReplayOutcome::Applied]);
        assert_eq!(fs::read_to_string(&password_file).await?, "");
        assert_eq!(
            credentials
                .open("router", CredentialKind::Password)?
                .expose_secret(),
            password
        );
        let sealed = credentials.sealed_path("router", CredentialKind::Password)?;
        let stored = registry.get("router")?.profile.password_file;
        assert_eq!(stored.as_ref(), Some(&sealed));
        let routers = fs::read_to_string(state.dir().join("routers.json")).await?;
        assert!(routers.contains(&serde_json::to_string(&sealed)?));
        assert!(!changes.client().is_bootstrap().await?);
        assert_eq!(registry.poll_info("router").await?.hw_id(), Some("KN-1811"));
        assert_eq!(backups.list("router")?.len(), 1);
        assert!(!serde_json::to_string(&verify_chain(state.dir())?)?.contains(password));
        drop(changes);
        handle.shutdown().await?;
        Ok(())
    }
}
