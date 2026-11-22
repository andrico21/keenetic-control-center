//! The supervisor against real kit servers on loopback ports, with
//! `server.shutdown_timeout` = 1 s and real time (no paused clock: real sockets).

extern crate alloc;

mod client;
mod dedicated;
mod fixture;
mod restart;
mod section;
mod services;
mod shutdown;
mod startup;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};

use kcc_app::{mcp_settings::document::McpOverrides, settings::mcp_schema::Endpoint};
use tokio::{
    sync::{Mutex, mpsc},
    time::timeout,
};

use super::supervisor::{Hook, Stage, Windows};

/// Test result.
pub(super) type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// The longest a test waits for one expected event.
const EVENT_LIMIT: Duration = Duration::from_secs(60);

/// Short windows for tests whose health check or rebind is expected to fail.
pub(super) const SHORT: Windows = Windows {
    health: Duration::from_secs(2),
    rebind: Duration::from_secs(2),
};

/// A hook running `pause` at every stage.
pub(super) fn hook<F, P>(pause: F) -> Hook
where
    F: Fn(Stage) -> P + Send + Sync + 'static,
    P: Future<Output = ()> + Send + 'static,
{
    Hook {
        pause: Some(Arc::new(move |stage| Box::pin(pause(stage)))),
    }
}

/// The stages a [`holding`] hook reports, and the releases of its holds.
pub(super) struct Holds {
    /// Every stage reached, in order.
    pub(super) reached: mpsc::UnboundedReceiver<Stage>,
    /// Releases one hold; dropped, no stage is held any more.
    pub(super) release: Option<mpsc::UnboundedSender<()>>,
}

impl Holds {
    /// Waits until `stage` is reached; the stages before it are returned.
    pub(super) async fn until(&mut self, stage: Stage) -> TestResult<Vec<Stage>> {
        let mut before = Vec::new();
        loop {
            let reached = timeout(EVENT_LIMIT, self.reached.recv())
                .await?
                .ok_or("the hook is gone")?;
            if reached == stage {
                return Ok(before);
            }
            before.push(reached);
        }
    }

    /// Releases the current hold.
    pub(super) fn release(&self) -> TestResult {
        self.release
            .as_ref()
            .ok_or("no hold left")?
            .send(())
            .map_err(|_closed| "the hook is gone".into())
    }

    /// Releases the current hold and holds nothing any more.
    pub(super) fn release_all(&mut self) -> TestResult {
        self.release()?;
        self.release = None;
        Ok(())
    }
}

/// A hook that reports every stage and holds each one of `stages` until released.
pub(super) fn holding(stages: &[Stage]) -> (Hook, Holds) {
    let held = stages.to_vec();
    let (seen, reached) = mpsc::unbounded_channel();
    let (release, receiver) = mpsc::unbounded_channel::<()>();
    let released = Arc::new(Mutex::new(receiver));
    let hook = hook(move |at| {
        let (report, gate, holds) = (seen.clone(), Arc::clone(&released), held.clone());
        async move {
            let _reported = report.send(at);
            if holds.contains(&at) {
                let _released = gate.lock().await.recv().await;
            }
        }
    });
    (
        hook,
        Holds {
            reached,
            release: Some(release),
        },
    )
}

/// A change setting `endpoint`.
pub(super) fn endpoint(value: Endpoint) -> McpOverrides {
    let mut change = McpOverrides::default();
    change.endpoint = Some(value);
    change
}

/// Waits at most [`EVENT_LIMIT`] for `future`.
pub(super) async fn bounded<F>(future: F) -> TestResult<F::Output>
where
    F: Future,
{
    Ok(timeout(EVENT_LIMIT, future).await?)
}
