//! The revert of a failed restart: stop the new generations, apply the previous live
//! settings again, and serve each previous generation on its address again.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::mcp_settings::ListenerKind;
use tokio::time::{Instant, interval};

use super::{
    ListenerError, Restarted, RevertReason,
    build::Keys,
    generation::{Previous, RETRY, StartError},
    name,
    restart::reapply,
    supervisor::{Stage, Supervisor, blocking_build},
};
use crate::server_error::ServerError;

/// Stops the new generations of `kinds`, applies the previous live settings again when
/// `applied`, and serves each of `previous` on its address again.
///
/// # Errors
///
/// [`ListenerError::ShuttingDown`] when a previous generation cannot serve again within
/// the rebind window: the supervisor then stops `kcc serve` with an error.
// NOT cancel-safe: as `restart`.
pub(super) async fn revert(
    supervisor: &mut Supervisor,
    (kinds, previous): (&[ListenerKind], Vec<Previous>),
    reason: RevertReason,
    applied: bool,
) -> Result<Restarted, ListenerError> {
    tracing::warn!(
        ?reason,
        "listener restart failed; serving the previous listeners again"
    );
    let (reload, wait) = (
        Arc::clone(&supervisor.shared.reload),
        supervisor.shutdown_wait(),
    );
    for kind in kinds.iter().copied() {
        drop(supervisor.listeners.stop(kind, &reload, wait).await);
    }
    if applied {
        reapply(supervisor).await;
    }
    for generation in previous {
        if let Err(failure) = rebind(supervisor, &generation).await {
            let listener = name(generation.kind);
            tracing::error!(listener, reason = %failure, "the previous listener cannot serve again; stopping kcc serve");
            supervisor.fatal = Some(ServerError::Rebind {
                listener,
                reason: failure,
            });
            return Err(ListenerError::ShuttingDown);
        }
    }
    Ok(Restarted::Reverted(reason))
}

/// Serves `previous` on its address again, retrying a bind refused while the address is
/// still in use until the rebind window ends.
// NOT cancel-safe: as `Listeners::start`.
async fn rebind(supervisor: &mut Supervisor, previous: &Previous) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(supervisor.windows.rebind)
        .ok_or_else(|| "rebind window overflows the clock".to_owned())?;
    let mut ticks = interval(RETRY);
    let listener = name(previous.kind);
    loop {
        let _: Instant = ticks.tick().await;
        let built = blocking_build(
            &supervisor.shared,
            previous.kind,
            &previous.settings,
            Keys::BestEffort,
        )
        .await
        .map_err(|error| error.to_string())?;
        let failure = match supervisor
            .listeners
            .start(built, Some(previous.address))
            .await
        {
            Ok(_address) => break,
            Err(StartError::Bind(error)) => error.to_string(),
            Err(StartError::Serve(reason)) => reason,
        };
        if Instant::now() >= deadline {
            return Err(failure);
        }
        tracing::warn!(listener, reason = %failure, "the previous listener cannot bind yet; retrying");
        supervisor.hook.at(Stage::Rebind).await;
    }
    let (reload, window) = (
        Arc::clone(&supervisor.shared.reload),
        supervisor.windows.health,
    );
    if let Err(error) = supervisor
        .listeners
        .register(previous.kind, &reload, window)
        .await
    {
        tracing::error!(listener, %error, "the previous listener keeps its start-up keys and roles until the next reload");
    }
    Ok(())
}
