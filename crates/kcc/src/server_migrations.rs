//! Startup audit events for migrated router credentials.

use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::{
    audit::{Actor, ActorKind, AuditError, AuditEvent, AuditLog},
    credentials::MigrationState,
};

/// Appends one audit event for each credential migrated during startup.
///
/// # Errors
/// Returns an audit writer error when an event cannot be appended.
// NOT cancel-safe: an event may be appended after cancellation while awaiting acknowledgement.
pub(super) async fn append_credential_events(
    audit: &AuditLog,
    migrations: Vec<(String, MigrationState)>,
) -> Result<(), AuditError> {
    for (router, migration) in migrations {
        if !matches!(migration, MigrationState::Current) {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            let event = AuditEvent::new(
                timestamp,
                Actor::new(ActorKind::System, "system".to_owned()),
                "router.credential_migrated".to_owned(),
            )
            .with_router(router)
            .with_result("success".to_owned(), format!("startup-{timestamp}"));
            drop(audit.append(event).await?);
        }
    }
    Ok(())
}
