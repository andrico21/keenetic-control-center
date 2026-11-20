//! Reading the notification state off the async executor, and what the page shows of it.

use core::error::Error;

use kcc_app::{
    notify_store::{NotifyRuntime, NotifySettings},
    persist::{StateError, StateStore},
};
use tokio::task::spawn_blocking;

use super::{NotifyControl, NotifyStatus};
use crate::WebState;

/// A failure the page answers with its error page.
pub(super) type Failure = Box<dyn Error + Send + Sync>;

/// What the page shows: the stored settings and delivery state, and the running
/// notifier's status when one is attached.
pub(super) struct Seen {
    /// `notify.json`, the defaults when absent.
    settings: NotifySettings,
    /// `notify_state.json`, empty when absent.
    runtime: NotifyRuntime,
    /// The running notifier's status.
    status: Option<NotifyStatus>,
}

impl Seen {
    /// `notify.json`, the defaults when absent.
    pub(super) const fn settings(&self) -> &NotifySettings {
        &self.settings
    }

    /// `notify_state.json`, empty when absent.
    pub(super) const fn runtime(&self) -> &NotifyRuntime {
        &self.runtime
    }

    /// The running notifier's status.
    pub(super) const fn status(&self) -> Option<&NotifyStatus> {
        self.status.as_ref()
    }
}

/// The state directory of the attached administration services.
///
/// # Errors
///
/// When no administration services are attached.
pub(super) fn store(state: &WebState) -> Result<StateStore, Failure> {
    state
        .admin()
        .map(|admin| admin.state().clone())
        .ok_or_else(|| "administration services are not attached".into())
}

/// Runs `work` on a blocking thread.
///
/// # Errors
///
/// The work's own error, or the blocking task's failure.
// cancel-safe: the work runs whole on its thread even if the future is dropped; only its result is
// lost.
pub(super) async fn blocking<T, E, F>(work: F) -> Result<T, Failure>
where
    T: Send + 'static,
    E: Error + Send + Sync + 'static,
    F: FnOnce() -> Result<T, E> + Send + 'static,
{
    Ok(spawn_blocking(work).await??)
}

/// The stored settings and delivery state, and the notifier's status.
///
/// # Errors
///
/// Missing administration services, state or blocking-task failures.
// cancel-safe: it only reads local state.
pub(super) async fn seen(state: &WebState) -> Result<Seen, Failure> {
    let store = store(state)?;
    let (settings, runtime) = blocking(move || read(&store)).await?;
    Ok(Seen {
        settings,
        runtime,
        status: state.notify().map(NotifyControl::status),
    })
}

/// `notify.json` and `notify_state.json`, their defaults when absent.
///
/// # Errors
///
/// State failures.
fn read(store: &StateStore) -> Result<(NotifySettings, NotifyRuntime), StateError> {
    Ok((
        store.read()?.unwrap_or_default(),
        store.read()?.unwrap_or_default(),
    ))
}
