//! Management endpoint transitions within an elapsed-time budget.

use core::{str::FromStr as _, time::Duration};

use kcc_app::workflow::ReplayCompletionError;
use kcc_rci::RouterUrl;
use tokio::time::timeout;

use super::{Applier, ApplyError, finish};
use crate::planner::PlannedLine;

/// Reconnects after a management write while preserving audit failures as failures.
///
/// # Errors
/// Returns audit, reconnect, or router recovery failures.
// NOT cancel-safe: a credential transition may persist before cancellation.
pub(super) async fn complete_line(
    applier: &mut Applier,
    line: &PlannedLine,
    completion: Result<(), ReplayCompletionError>,
) -> Result<(), ApplyError> {
    match completion {
        Ok(()) | Err(ReplayCompletionError::ReadBack) => {
            if !applier
                .plan
                .phases
                .management
                .iter()
                .any(|entry| entry.source_index == line.source_index)
            {
                return match completion {
                    Ok(()) => Ok(()),
                    Err(_error) => finish::recover(applier).await,
                };
            }
            applier.credential.applied(line.expose_command());
            let client = applier.changes.client();
            let password_change = line.expose_command().starts_with("user ");
            let url = RouterUrl::from_str(if password_change {
                client.router_url().as_str()
            } else {
                applier
                    .plan
                    .reconnect_url
                    .as_deref()
                    .unwrap_or_else(|| client.router_url().as_str())
            })
            .map_err(|_error| ApplyError::Validation)?;
            let started = applier.options.clock.now();
            let budget = Duration::from_secs(120);
            while let Some(remaining) =
                budget.checked_sub(applier.options.clock.now().saturating_sub(started))
            {
                if remaining.is_zero() {
                    break;
                }
                if timeout(
                    remaining,
                    applier
                        .changes
                        .reconnect(url.clone(), applier.credential.current()),
                )
                .await
                .is_ok_and(|result| result.is_ok())
                    && applier.options.clock.now().saturating_sub(started) <= budget
                {
                    return Ok(());
                }
                let wait_budget =
                    budget.saturating_sub(applier.options.clock.now().saturating_sub(started));
                if wait_budget.is_zero() {
                    break;
                }
                applier
                    .options
                    .clock
                    .wait(Duration::from_secs(1).min(wait_budget))
                    .await;
            }
            finish::recover(applier).await
        }
        Err(ReplayCompletionError::Audit | _) => Err(ApplyError::Workflow),
    }
}
