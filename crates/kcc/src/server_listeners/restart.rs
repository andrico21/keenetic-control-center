//! One change in the serialized section: the version check, the restart of every listener
//! a candidate names as one unit, the revert, the live apply and the commit.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    mcp_settings::{
        Candidate, Effective, ListenerKind, SettingsError, commit, document::McpSettingsDocument,
    },
    settings::McpConfig,
};
use kcc_web::admin::ReloadError;
use tokio::task::spawn_blocking;

use super::{
    ListenerError, Restarted, RevertReason,
    build::{Built, Keys},
    generation::StartError,
    name,
    revert::revert,
    supervisor::{Stage, Supervisor, blocking_build},
};

/// Restarts every listener `candidate` names, then applies and saves it.
///
/// Order: version check, build and validate every new generation, stop the previous
/// ones, serve, register and health-check each new one, apply the live settings, save.
/// A failure from the serve step on stops the new generations and serves the previous
/// ones again on their addresses, with the previous live settings.
// NOT cancel-safe: dropped (a termination), the generations started so far stay recorded
// and are stopped by the supervisor; the settings are neither applied nor saved.
pub(super) async fn restart(
    supervisor: &mut Supervisor,
    candidate: &Candidate,
) -> Result<Restarted, ListenerError> {
    check_version(supervisor, candidate).await?;
    let next = candidate.effective().settings();
    let kinds = candidate.restart().to_vec();
    let mut built = Vec::new();
    for kind in kinds.iter().copied().filter(|kind| wanted(*kind, next)) {
        built.push(
            blocking_build(&supervisor.shared, kind, next, Keys::Required)
                .await
                .map_err(|source| ListenerError::Build {
                    listener: name(kind),
                    source,
                })?,
        );
    }
    let (reload, wait) = (
        Arc::clone(&supervisor.shared.reload),
        supervisor.shutdown_wait(),
    );
    let mut previous = Vec::new();
    for kind in kinds.iter().copied() {
        previous.extend(supervisor.listeners.stop(kind, &reload, wait).await);
    }
    supervisor.hook.at(Stage::Stopped).await;
    if let Err(reason) = serve_new(supervisor, built).await {
        return revert(supervisor, (&kinds, previous), reason, false).await;
    }
    if let Err(error) = apply(supervisor, candidate.effective()).await {
        return revert(
            supervisor,
            (&kinds, previous),
            RevertReason::Apply(error),
            true,
        )
        .await;
    }
    match save(supervisor, candidate).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return revert(
                supervisor,
                (&kinds, previous),
                RevertReason::Commit(error),
                true,
            )
            .await;
        }
        Err(task) => {
            return revert(
                supervisor,
                (&kinds, previous),
                RevertReason::Task(task),
                true,
            )
            .await;
        }
    }
    supervisor.applied = candidate.effective().clone();
    supervisor.listeners.clear_notes(&kinds);
    Ok(Restarted::Applied)
}

/// Applies and saves `candidate`, which restarts no listener.
// NOT cancel-safe: dropped (a termination) after the apply, the settings stay applied but
// unsaved until the process exits.
pub(super) async fn apply_live(
    supervisor: &mut Supervisor,
    candidate: &Candidate,
) -> Result<(), ListenerError> {
    if !candidate.restart().is_empty() {
        return Err(ListenerError::RestartRequired);
    }
    check_version(supervisor, candidate).await?;
    if let Err(error) = apply(supervisor, candidate.effective()).await {
        reapply(supervisor).await;
        return Err(ListenerError::Apply(error));
    }
    let saved = save(supervisor, candidate).await;
    if matches!(saved, Ok(Ok(()))) {
        supervisor.applied = candidate.effective().clone();
        return Ok(());
    }
    reapply(supervisor).await;
    Err(match saved {
        Ok(Err(error)) => ListenerError::Commit(error),
        Err(task) => ListenerError::Task(task),
        Ok(Ok(())) => ListenerError::ShuttingDown,
    })
}

/// Refuses `candidate` when `mcp_settings.json` changed since it was planned.
// cancel-safe: only reads.
async fn check_version(
    supervisor: &Supervisor,
    candidate: &Candidate,
) -> Result<(), ListenerError> {
    let state = supervisor.shared.state.clone();
    let revision = spawn_blocking(move || state.read::<McpSettingsDocument>())
        .await
        .map_err(|error| ListenerError::Task(error.to_string()))?
        .map_err(|error| ListenerError::Settings(SettingsError::State(error)))?
        .unwrap_or_default()
        .revision;
    if revision == candidate.base_version() {
        Ok(())
    } else {
        Err(ListenerError::SettingsChanged)
    }
}

/// Whether `kind` runs with `settings`.
const fn wanted(kind: ListenerKind, settings: &McpConfig) -> bool {
    match kind {
        ListenerKind::Main => true,
        ListenerKind::Dedicated | _ => settings.dedicated.enabled,
    }
}

/// Serves each of `built`, registers it with the reload fan-out (which installs the
/// current keys and roles) and health-checks it.
// NOT cancel-safe: as `Listeners::start`.
pub(super) async fn serve_new(
    supervisor: &mut Supervisor,
    built: Vec<Built>,
) -> Result<(), RevertReason> {
    let reload = Arc::clone(&supervisor.shared.reload);
    let window = supervisor.windows.health;
    for generation in built {
        let listener = generation.kind;
        let _address =
            supervisor.listeners.start(generation, None).await.map_err(
                |failure| match failure {
                    StartError::Bind(error) => RevertReason::Bind {
                        listener,
                        reason: error.to_string(),
                    },
                    StartError::Serve(reason) => RevertReason::Serve { listener, reason },
                },
            )?;
        supervisor.hook.at(Stage::Serving).await;
        supervisor
            .listeners
            .register(listener, &reload, window)
            .await
            .map_err(|reason| RevertReason::Register { listener, reason })?;
        let (address, probe) =
            supervisor
                .listeners
                .probe(listener)
                .ok_or_else(|| RevertReason::Health {
                    listener,
                    reason: "the listener stopped".to_owned(),
                })?;
        spawn_blocking(move || probe.check(address, window))
            .await
            .map_err(|error| error.to_string())
            .and_then(|checked| checked)
            .map_err(|reason| RevertReason::Health { listener, reason })?;
    }
    Ok(())
}

/// Applies `effective`'s live settings off the async executor.
// cancel-safe: the apply runs to completion on its own thread.
async fn apply(supervisor: &Supervisor, effective: &Effective) -> Result<(), ReloadError> {
    let (apply, settings) = (Arc::clone(&supervisor.apply), effective.clone());
    spawn_blocking(move || apply.apply(&settings))
        .await
        .map_err(|error| ReloadError::Failed(error.to_string()))?
}

/// Applies the live settings that were applied before this change again; a failure is
/// logged.
// cancel-safe: as `apply`.
pub(super) async fn reapply(supervisor: &Supervisor) {
    let previous = supervisor.applied.clone();
    if let Err(error) = apply(supervisor, &previous).await {
        tracing::error!(%error, "the previous live MCP settings could not be applied again");
    }
}

/// Writes `candidate` to `mcp_settings.json`; `Err` when the write task ended abnormally.
// cancel-safe: the write runs to completion on its own thread.
async fn save(
    supervisor: &Supervisor,
    candidate: &Candidate,
) -> Result<Result<(), SettingsError>, String> {
    let (state, saved) = (supervisor.shared.state.clone(), candidate.clone());
    spawn_blocking(move || commit(&state, &saved))
        .await
        .map_err(|error| error.to_string())
}
