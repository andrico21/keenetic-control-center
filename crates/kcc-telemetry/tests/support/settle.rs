//! Waiting for the exact state a paused-time test needs.

use core::{error::Error, time::Duration};
use std::time::Instant;

use tokio::task;

/// Real time a wait may take before the test fails.
const BOUND: Duration = Duration::from_secs(5);

/// Yields until `ready` holds. Yielding keeps the runtime busy, so the paused clock does not
/// advance: the state is reached at the current virtual instant. Fails after `BOUND` of real
/// time instead of hanging.
pub(crate) async fn settle<F>(what: &str, mut ready: F) -> Result<(), Box<dyn Error>>
where
    F: AsyncFnMut() -> Result<bool, Box<dyn Error>>,
{
    let started = Instant::now();
    while !ready().await? {
        if started.elapsed() > BOUND {
            return Err(format!("not reached within {BOUND:?} of real time: {what}").into());
        }
        task::yield_now().await;
    }
    Ok(())
}
