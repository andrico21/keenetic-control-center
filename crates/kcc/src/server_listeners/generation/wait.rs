//! The wait for a stopped generation's address.

use core::{net::SocketAddr, time::Duration};
use std::net::TcpListener as StdListener;

use tokio::time::{Instant, interval};

use super::RETRY;

/// Waits at most `window` until `address` can be bound again (a stopped generation's
/// TLS and metrics listeners close their sockets on their own tasks).
// cancel-safe: holds no socket across an await.
pub(super) async fn wait_free(address: SocketAddr, window: Duration) {
    let deadline = Instant::now().checked_add(window);
    let mut ticks = interval(RETRY);
    loop {
        match StdListener::bind(address) {
            Ok(free) => return drop(free),
            Err(error) if deadline.is_some_and(|end| Instant::now() < end) => {
                tracing::debug!(%address, %error, "stopped listener's address still in use");
            }
            Err(error) => {
                tracing::warn!(%address, %error, "stopped listener's address still in use; starting anyway");
                return;
            }
        }
        let _: Instant = ticks.tick().await;
    }
}
