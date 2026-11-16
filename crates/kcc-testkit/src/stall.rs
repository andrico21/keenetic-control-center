//! Holding a router's requests before it answers them, so a test can act while one waits.

use alloc::sync::Arc;

use tokio::sync::watch;

/// The router's door: open, every request passes; closed, each waits until it opens.
#[derive(Debug)]
pub(crate) struct Gate {
    /// Whether requests pass.
    open: watch::Sender<bool>,
    /// How many requests waited at the closed door so far.
    held: watch::Sender<u64>,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            open: watch::Sender::new(true),
            held: watch::Sender::new(0),
        }
    }
}

impl Gate {
    /// Waits while the door is closed.
    // cancel-safe: only waits.
    pub(crate) async fn pass(&self) {
        let mut open = self.open.subscribe();
        if *open.borrow_and_update() {
            return;
        }
        self.held.send_modify(|held| *held = held.saturating_add(1));
        if open.wait_for(|passes| *passes).await.is_err() {
            tracing::debug!("the router stopped while a request was held");
        }
    }

    /// Closes the door; the receiver counts the requests held from now on.
    fn close(&self) -> watch::Receiver<u64> {
        let _: u64 = self.held.send_replace(0);
        let _: bool = self.open.send_replace(false);
        self.held.subscribe()
    }

    /// Opens the door.
    fn reopen(&self) {
        let _: bool = self.open.send_replace(true);
    }
}

/// Requests of one router held until this is dropped; see [`crate::Handle::stall`].
#[derive(Debug)]
#[must_use = "dropping the stall lets the held requests through"]
pub struct Stall {
    /// The door, absent for a server without router state.
    gate: Option<Arc<Gate>>,
    /// Requests held so far.
    held: watch::Receiver<u64>,
}

impl Stall {
    /// Closes `gate` until the stall is dropped.
    pub(crate) fn new(gate: Option<Arc<Gate>>) -> Self {
        let held = gate
            .as_ref()
            .map_or_else(|| watch::channel(0).1, |found| found.close());
        Self { gate, held }
    }

    /// Waits until a request reached the router and is held; `false` when none can be.
    // cancel-safe: only waits.
    #[inline]
    pub async fn held(&mut self) -> bool {
        self.held.wait_for(|held| *held > 0).await.is_ok()
    }
}

impl Drop for Stall {
    #[inline]
    fn drop(&mut self) {
        if let Some(gate) = &self.gate {
            gate.reopen();
        }
    }
}
