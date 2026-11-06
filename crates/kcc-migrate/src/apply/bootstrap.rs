//! Factory credential establishment before recovery arming.

use kcc_app::workflow::{ChangeSet, CliCommand, ReplayOutcome, ReplayPolicy};
use kcc_domain::RouterCtx;
use kcc_rci::auth::Credentials;

use super::{ApplyError, ApplyRequest};

/// Establishes and persists factory credentials before any other mutation.
///
/// # Errors
/// Returns missing-password, protected replay, or credential-transition failures.
// NOT cancel-safe: the password may change before the new credential is persisted.
pub(super) async fn initialize(
    request: &ApplyRequest,
    changes: &mut ChangeSet,
    ctx: &RouterCtx,
) -> Result<(), ApplyError> {
    if !ctx
        .client
        .is_bootstrap()
        .await
        .map_err(|_error| ApplyError::Workflow)?
    {
        return Ok(());
    }
    let password = request
        .options
        .admin_password
        .as_ref()
        .ok_or(ApplyError::PasswordRequired)?;
    let validated = ctx
        .catalog
        .validate_secret("user password plain", "password", password.clone())
        .map_err(|_issues| ApplyError::Validation)?;
    let command = CliCommand::from_template(validated, "user admin password plain {/password}")
        .map_err(|_error| ApplyError::Validation)?;
    let result = changes
        .replay(&[command], ReplayPolicy::StopOnError)
        .await
        .map_err(|_error| ApplyError::Workflow)?;
    if result.outcomes != [ReplayOutcome::Applied] {
        return Err(ApplyError::Stopped);
    }
    changes
        .reconnect(
            ctx.client.router_url().clone(),
            Some(Credentials::new("admin".to_owned(), password.clone())),
        )
        .await
        .map_err(|_error| ApplyError::Workflow)
}
