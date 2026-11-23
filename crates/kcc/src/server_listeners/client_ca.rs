//! The replacement of the client CA in the serialized section.
//!
//! The CA is stored, then every listener whose client-certificate sign-in is on restarts
//! as one unit; a failure puts the previous CA back before the previous listeners serve
//! again.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    mcp_settings::{
        ListenerKind,
        client_ca::{CaError, read_mtls_ca, restore_mtls_ca, store_mtls_ca},
    },
    persist::StateStore,
    settings::{McpConfig, mcp_schema::MtlsMode},
};
use tokio::task::spawn_blocking;

use super::{
    ListenerError, Restarted,
    build::Keys,
    name,
    restart::serve_new,
    revert::revert,
    supervisor::{Stage, Supervisor, blocking_build},
};

/// Stores `pem` as the client CA and restarts the listeners using it.
///
/// Refused with [`ListenerError::ConfirmationRequired`] before anything changes when a
/// running listener's client-certificate sign-in is on and the actor did not re-enter the
/// password (`confirmed`). Without such a listener the CA is only stored.
// NOT cancel-safe: dropped (a termination) after the store, the new CA stays stored and the
// generations started so far are stopped by the supervisor.
pub(super) async fn replace(
    supervisor: &mut Supervisor,
    pem: Vec<u8>,
    confirmed: bool,
) -> Result<Restarted, ListenerError> {
    let users: Vec<(ListenerKind, McpConfig)> = supervisor
        .listeners
        .running()
        .into_iter()
        .filter(|(kind, settings)| mtls_of(*kind, settings) != MtlsMode::Off)
        .collect();
    if !users.is_empty() && !confirmed {
        return Err(ListenerError::ConfirmationRequired);
    }
    let state = supervisor.shared.state.clone();
    let previous = spawn_blocking(move || stored(&state, &pem))
        .await
        .map_err(|error| ListenerError::Task(error.to_string()))?
        .map_err(ListenerError::ClientCa)?;
    if users.is_empty() {
        return Ok(Restarted::Applied);
    }
    let mut built = Vec::new();
    for (kind, settings) in &users {
        match blocking_build(&supervisor.shared, *kind, settings, Keys::Required).await {
            Ok(generation) => built.push(generation),
            Err(source) => {
                put_back(supervisor, previous).await?;
                return Err(ListenerError::Build {
                    listener: name(*kind),
                    source,
                });
            }
        }
    }
    let kinds: Vec<ListenerKind> = users.iter().map(|(kind, _settings)| *kind).collect();
    let (reload, wait) = (
        Arc::clone(&supervisor.shared.reload),
        supervisor.shutdown_wait(),
    );
    let mut stopped = Vec::new();
    for kind in kinds.iter().copied() {
        stopped.extend(supervisor.listeners.stop(kind, &reload, wait).await);
    }
    supervisor.hook.at(Stage::Stopped).await;
    if let Err(reason) = serve_new(supervisor, built).await {
        if let Err(error) = put_back(supervisor, previous).await {
            tracing::error!(%error, "the previous client CA could not be put back");
        }
        return revert(supervisor, (&kinds, stopped), reason, false).await;
    }
    supervisor.listeners.clear_notes(&kinds);
    Ok(Restarted::Applied)
}

/// The client-certificate sign-in of the `kind` listener in `settings`.
const fn mtls_of(kind: ListenerKind, settings: &McpConfig) -> MtlsMode {
    match kind {
        ListenerKind::Main => settings.auth.main.mtls,
        ListenerKind::Dedicated | _ => settings.auth.dedicated.mtls,
    }
}

/// Stores `pem` as the client CA of `state`; the file it replaced, if any.
///
/// # Errors
///
/// The CA's refusal, or the previous file could not be read.
fn stored(state: &StateStore, pem: &[u8]) -> Result<Option<Vec<u8>>, CaError> {
    let previous = read_mtls_ca(state)?;
    let _subjects = store_mtls_ca(state, pem)?;
    Ok(previous)
}

/// Puts `previous` back as the client CA (removes it when there was none).
// cancel-safe: the write runs to completion on its own thread.
async fn put_back(supervisor: &Supervisor, previous: Option<Vec<u8>>) -> Result<(), ListenerError> {
    let state = supervisor.shared.state.clone();
    spawn_blocking(move || restore_mtls_ca(&state, previous.as_deref()))
        .await
        .map_err(|error| ListenerError::Task(error.to_string()))?
        .map_err(ListenerError::ClientCa)
}
