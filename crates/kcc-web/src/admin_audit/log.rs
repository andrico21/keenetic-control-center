//! The audit log as the page shows it: verified once and kept while its files stay as
//! they were.

extern crate alloc;

use alloc::sync::Arc;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError},
    time::SystemTime,
};

use kcc_app::audit::{AuditEntry, AuditError, chain_files, read_entries, verify_chain};
use tokio::task::{JoinError, spawn_blocking};

/// The state of the hash chain.
#[derive(Debug)]
pub(super) enum Chain {
    /// Every entry verified.
    Intact(usize),
    /// The chain breaks at this sequence number.
    Broken(u64),
    /// The log could not be read.
    Unreadable,
}

/// The audit log read once.
#[derive(Debug)]
pub(super) struct Log {
    /// Chain verification result.
    chain: Chain,
    /// Every readable entry, in chain order.
    entries: Vec<AuditEntry>,
}

impl Log {
    /// A log with `chain` and `entries`.
    pub(super) const fn new(chain: Chain, entries: Vec<AuditEntry>) -> Self {
        Self { chain, entries }
    }

    /// The chain verification result.
    pub(super) const fn chain(&self) -> &Chain {
        &self.chain
    }

    /// Every readable entry, in chain order.
    pub(super) fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

/// Name, length and modification time of every file the verification reads. Two equal
/// stamps mean the verification would read the same bytes.
#[derive(Debug, PartialEq, Eq)]
struct Stamp(Vec<(PathBuf, u64, Option<SystemTime>)>);

impl Stamp {
    /// The stamp of the audit files in `dir`, or `None` when one cannot be listed or
    /// inspected.
    fn of(dir: &Path) -> Option<Self> {
        let files = chain_files(dir).ok()?;
        files
            .into_iter()
            .map(|path| {
                let meta = fs::metadata(&path).ok()?;
                Some((path, meta.len(), meta.modified().ok()))
            })
            .collect::<Option<Vec<_>>>()
            .map(Self)
    }
}

/// The kept log and the stamp it was read under.
type Kept = Option<(Stamp, Arc<Log>)>;

/// The last verified log, with the stamp of the files it was read from.
#[derive(Debug, Clone, Default)]
pub(crate) struct LogCache {
    /// The one kept log.
    slot: Arc<Mutex<Kept>>,
}

impl LogCache {
    /// The log in `dir`: the kept one while its files are unchanged, otherwise a fresh
    /// read that is verified and kept. Runs off the async executor.
    ///
    /// # Errors
    ///
    /// Returns the join error when the blocking read panicked or was cancelled.
    // cancel-safe: the read runs to completion on a blocking thread; an abandoned call
    // only leaves its result in the cache.
    pub(super) async fn read(&self, dir: PathBuf) -> Result<Arc<Log>, JoinError> {
        let cache = self.clone();
        spawn_blocking(move || {
            Stamp::of(&dir).map_or_else(
                || Arc::new(load(&dir)),
                |stamp| cache.get_or_load(stamp, || load(&dir)),
            )
        })
        .await
    }

    /// The kept log when `stamp` is the one it was read under, otherwise `load()`'s.
    /// An unreadable log is not kept, so the next view tries again.
    fn get_or_load(&self, stamp: Stamp, load: impl FnOnce() -> Log) -> Arc<Log> {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((held, log)) = slot.as_ref()
            && *held == stamp
        {
            return Arc::clone(log);
        }
        let log = Arc::new(load());
        *slot = match log.chain {
            Chain::Unreadable => None,
            Chain::Intact(_) | Chain::Broken(_) => Some((stamp, Arc::clone(&log))),
        };
        log
    }
}

/// Verifies the chain and reads the entries.
fn load(dir: &Path) -> Log {
    match verify_chain(dir) {
        Ok(entries) => Log::new(Chain::Intact(entries.len()), entries),
        Err(AuditError::Chain { seq }) => Log::new(
            Chain::Broken(seq),
            read_entries(dir).unwrap_or_else(|error| {
                tracing::error!(%error, "entries of the broken audit log could not be read");
                Vec::new()
            }),
        ),
        Err(error) => {
            tracing::error!(%error, "audit log could not be read");
            Log::new(Chain::Unreadable, Vec::new())
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    use core::{
        error::Error,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tempfile::TempDir;

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    fn intact() -> Log {
        Log {
            chain: Chain::Intact(0),
            entries: Vec::new(),
        }
    }

    fn stamp(len: u64) -> Stamp {
        Stamp(vec![(PathBuf::from("audit.jsonl"), len, None)])
    }

    /// W1-08: a view of unchanged files reuses the verified log, and any change of the
    /// files verifies again.
    #[test]
    fn the_log_is_verified_once_while_its_files_are_unchanged() {
        let cache = LogCache::default();
        let loads = AtomicUsize::new(0);
        let load = || {
            let _: usize = loads.fetch_add(1, Ordering::SeqCst);
            intact()
        };
        let first = cache.get_or_load(stamp(10), load);
        let second = cache.get_or_load(stamp(10), load);
        assert!(Arc::ptr_eq(&first, &second), "the kept log is served");
        assert_eq!(loads.load(Ordering::SeqCst), 1, "verified once");
        drop(cache.get_or_load(stamp(11), load));
        assert_eq!(
            loads.load(Ordering::SeqCst),
            2,
            "a changed file verifies again"
        );
    }

    /// W1-08: a broken chain is kept under its stamp and still reported, an unreadable
    /// log is not kept.
    #[test]
    fn a_failure_is_kept_as_a_failure_and_an_unreadable_log_is_retried() {
        let cache = LogCache::default();
        let broken = || Log {
            chain: Chain::Broken(3),
            entries: Vec::new(),
        };
        drop(cache.get_or_load(stamp(1), broken));
        let again = cache.get_or_load(stamp(1), intact);
        assert!(matches!(again.chain, Chain::Broken(3)), "still broken");

        let unreadable = || Log {
            chain: Chain::Unreadable,
            entries: Vec::new(),
        };
        drop(cache.get_or_load(stamp(2), unreadable));
        let retried = cache.get_or_load(stamp(2), intact);
        assert!(matches!(retried.chain, Chain::Intact(_)), "read again");
    }

    /// W1-08: the stamp changes with an append and with a rewrite of the same length at
    /// another time.
    #[test]
    fn the_stamp_follows_length_and_modification_time() -> TestResult {
        let dir = TempDir::new()?;
        let active = dir.path().join("audit.jsonl");
        fs::write(&active, "a\n")?;
        let first = Stamp::of(dir.path()).ok_or("stamp")?;
        assert_eq!(Some(&first), Stamp::of(dir.path()).as_ref(), "stable");
        let file = fs::OpenOptions::new().write(true).open(&active)?;
        file.set_modified(SystemTime::now() + Duration::from_secs(60))?;
        assert_ne!(Some(&first), Stamp::of(dir.path()).as_ref(), "mtime");
        fs::write(&active, "a\nb\n")?;
        assert_ne!(Some(&first), Stamp::of(dir.path()).as_ref(), "length");
        Ok(())
    }
}
