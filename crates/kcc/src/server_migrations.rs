//! Audit events for router credentials migrated at startup or on first CLI use, and the
//! startup warning of routers whose password still sits in an external plaintext file.

use kcc_app::{
    accounts::{Clock as _, SystemClock},
    audit::{Actor, ActorKind, AuditError, AuditEvent, AuditLog, request_id},
    credentials::MigrationState,
    registry::{RegistryError, RouterRegistry},
};

/// Appends one audit event, naming only the router id, for each credential migrated
/// when `origin` (`startup` for `kcc serve`, `cli` for a CLI run) opened the state.
///
/// # Errors
/// Returns an audit writer error when an event cannot be appended.
// NOT cancel-safe: an event may be appended after cancellation while awaiting acknowledgement.
pub(super) async fn append_credential_events(
    audit: &AuditLog,
    migrations: Vec<(String, MigrationState)>,
    origin: &str,
) -> Result<(), AuditError> {
    for (router, migration) in migrations {
        if !matches!(migration, MigrationState::Current) {
            let event = AuditEvent::new(
                SystemClock::default().unix_seconds(),
                Actor::new(ActorKind::System, "system".to_owned()),
                "router.credential_migrated".to_owned(),
            )
            .with_router(router)
            .with_result("success".to_owned(), request_id::next(origin));
            drop(audit.append(event).await?);
        }
    }
    Ok(())
}

/// Logs one warning per Web UI or CLI router that still reads its password from an
/// external plaintext file, naming the command that seals it. The file is left alone.
///
/// # Errors
/// Returns a registry error when the profiles cannot be listed.
pub(super) fn warn_external_password_files(registry: &RouterRegistry) -> Result<(), RegistryError> {
    for (router, file) in registry.external_password_files()? {
        tracing::warn!(
            router = %router,
            file = %file.display(),
            "router {router} reads its password from an external plaintext file; seal it with `kcc router edit {router} --new-password --password-file {}`",
            file.display()
        );
    }
    Ok(())
}
