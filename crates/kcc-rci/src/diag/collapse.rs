//! Collapsing of identical warning lines within a window.

use alloc::collections::BTreeMap;
use core::time::Duration;
use std::time::Instant;

/// How long identical lines collapse into one.
const WINDOW: Duration = Duration::from_secs(60);

/// Most keys remembered at once; the oldest is forgotten first.
const MAX_KEYS: usize = 256;

/// One line's identity: router id, method, path and cause.
pub type DedupeKey = (String, String, String, String);

/// What to do with one line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Admit {
    /// Log it, noting how many identical lines were left out before it.
    Log {
        /// Identical lines left out since the last logged one.
        suppressed: u32,
    },
    /// Leave it out.
    Suppress,
}

/// The last logged time and the lines left out since, of one key.
#[derive(Clone, Copy, Debug)]
struct Seen {
    /// When the key was last logged.
    logged: Instant,
    /// Lines left out since then.
    suppressed: u32,
}

/// Collapses identical lines within 60 s into one; pure, on instants the caller passes.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct Deduper {
    /// Remembered keys.
    seen: BTreeMap<DedupeKey, Seen>,
}

impl Deduper {
    /// Decides whether the line `key` at `now` is logged.
    #[inline]
    pub fn admit(&mut self, key: DedupeKey, now: Instant) -> Admit {
        if let Some(seen) = self.seen.get_mut(&key) {
            if now.saturating_duration_since(seen.logged) < WINDOW {
                seen.suppressed = seen.suppressed.saturating_add(1);
                return Admit::Suppress;
            }
            let suppressed = seen.suppressed;
            *seen = Seen {
                logged: now,
                suppressed: 0,
            };
            return Admit::Log { suppressed };
        }
        if self.seen.len() >= MAX_KEYS
            && let Some(oldest) = self
                .seen
                .iter()
                .min_by_key(|(_stored, seen)| seen.logged)
                .map(|(stored, _seen)| stored.clone())
        {
            let _: Option<Seen> = self.seen.remove(&oldest);
        }
        let _: Option<Seen> = self.seen.insert(
            key,
            Seen {
                logged: now,
                suppressed: 0,
            },
        );
        Admit::Log { suppressed: 0 }
    }
}
