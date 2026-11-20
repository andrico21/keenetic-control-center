//! A preparation that stopped, and the router lease it keeps while the recovery timer may
//! still be armed.

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::workflow::ChangeSet;

use super::{ApplyError, ApplyOptions, Clock};

/// Why preparation stopped; with [`ApplyOptions::hold_armed_failure`], also the change set
/// (and so the router's lease) while the recovery timer may still be armed.
#[derive(Debug)]
pub(super) struct Unprepared {
    /// The failure handed to the caller.
    error: ApplyError,
    /// The lease to keep until the timer has run out.
    kept: Option<Box<Kept>>,
}

/// A lease kept for a recovery timer that may still be armed.
#[derive(Debug)]
struct Kept {
    /// Holds the router's lease.
    changes: ChangeSet,
    /// The apply's clock.
    clock: Arc<dyn Clock>,
    /// The recovery interval the timer was armed for.
    seconds: u64,
}

impl From<ApplyError> for Unprepared {
    #[inline]
    fn from(error: ApplyError) -> Self {
        Self { error, kept: None }
    }
}

impl Unprepared {
    /// `error`, which stopped preparation after recovery was armed under `options`:
    /// `changes` is kept when the timer may still be armed and `options` asks to hold such
    /// a failure, and dropped, freeing the lease, otherwise.
    pub(super) fn after_arm(error: ApplyError, changes: ChangeSet, options: &ApplyOptions) -> Self {
        let kept = (options.hold_armed_failure && error.recovery_armed()).then(|| {
            Box::new(Kept {
                changes,
                clock: Arc::clone(&options.clock),
                seconds: options.safety_seconds,
            })
        });
        Self { error, kept }
    }

    /// The failure handed to the caller.
    pub(super) const fn error(&self) -> ApplyError {
        self.error
    }

    /// Keeps the lease, when one is kept, until the timer has run out on the apply's
    /// clock: the interval and one second more from now, which is no earlier than the
    /// last arm or renewal the router may have received. Then frees it.
    // NOT cancel-safe: dropped while it waits, the lease is freed with the timer possibly
    // armed.
    pub(super) async fn hold(self) {
        if let Some(kept) = self.kept {
            let interval = Duration::from_secs(kept.seconds.saturating_add(1));
            kept.clock.wait(interval).await;
            drop(kept.changes);
        }
    }
}
