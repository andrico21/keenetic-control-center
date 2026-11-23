//! The registration of a started generation with the key and role reload fan-out.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::mcp_settings::ListenerKind;
use kcc_web::admin::{ReloadError, TransportReload};
use tokio::task::spawn_blocking;

use super::Listeners;

#[expect(
    clippy::multiple_inherent_impl,
    reason = "the reload registration lives beside the generations' start and stop, which keep the size rule"
)]
impl Listeners {
    /// Installs the current keys and roles into the `kind` generation and registers it
    /// with `reload`, waiting at most `window` for its handle.
    ///
    /// # Errors
    ///
    /// The kit handed out no handle in time, or the keys or roles could not be installed.
    // cancel-safe: dropped while waiting, the handle is kept for the next call.
    pub(in crate::server_listeners) async fn register(
        &mut self,
        kind: ListenerKind,
        reload: &Arc<TransportReload>,
        window: Duration,
    ) -> Result<(), String> {
        let generation = self
            .running
            .get_mut(&kind)
            .ok_or_else(|| "the listener is not running".to_owned())?;
        let receiver = generation
            .handles
            .as_mut()
            .ok_or_else(|| "the listener is registered already".to_owned())?;
        let handle = tokio::time::timeout(window, receiver)
            .await
            .map_err(|_elapsed| "no reload handle in time".to_owned())?
            .map_err(|_stopped| {
                "the listener stopped before it handed out its reload handle".to_owned()
            })?;
        generation.handles = None;
        let fan_out = Arc::clone(reload);
        spawn_blocking(move || fan_out.register(kind, handle))
            .await
            .map_err(|error| error.to_string())?
            .map_err(|error: ReloadError| error.to_string())
    }
}
