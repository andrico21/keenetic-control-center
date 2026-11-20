//! Followers of further state files.
//!
//! A component that keeps its own copy of a state file (the notifier, the scheduler)
//! registers the files and is told to reload once per pass in which any of them changed
//! on disk, and on SIGHUP.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt::Debug;
use std::{io, path::Path};

use super::{Tracked, Trigger, Version, observe};

/// A component that re-reads its state files when told they changed.
pub(crate) trait Follower: Debug + Send + Sync {
    /// Re-reads the watched files; called at most once per pass.
    fn reload(&self);
}

/// One follower and the files it watches.
#[derive(Debug)]
struct Entry {
    /// File names relative to the state directory.
    files: &'static [&'static str],
    /// Told to reload when a file changed.
    follower: Arc<dyn Follower>,
    /// The applied version of each file, in `files` order.
    tracked: Vec<Tracked<()>>,
}

/// Every registered follower.
#[derive(Debug, Default)]
pub(crate) struct Followers {
    /// In registration order.
    entries: Vec<Entry>,
}

impl Followers {
    /// Registers `follower` for `files`.
    pub(super) fn add(&mut self, files: &'static [&'static str], follower: Arc<dyn Follower>) {
        self.entries.push(Entry {
            files,
            follower,
            tracked: files.iter().map(|_file| Tracked::default()).collect(),
        });
    }

    /// The files to observe, per follower.
    pub(super) fn plan(&self) -> Vec<&'static [&'static str]> {
        self.entries.iter().map(|entry| entry.files).collect()
    }

    /// Applies one pass's `observed` versions (as [`observe_all`] of [`Self::plan`]
    /// returns them): a file whose version changed, and every file on a SIGHUP, reloads
    /// its follower once. The first pass only records. A file whose metadata cannot be
    /// read keeps its last state and is warned about once.
    pub(super) fn apply(&mut self, trigger: Trigger, observed: Vec<Vec<Version>>) {
        for (entry, versions) in self.entries.iter_mut().zip(observed) {
            let mut changed = false;
            for ((file, tracked), version) in
                entry.files.iter().zip(&mut entry.tracked).zip(versions)
            {
                if !tracked.due(trigger, version) {
                    continue;
                }
                if let Version::Unreadable(kind) = version {
                    tracked.failed(file, version, &io::Error::from(kind));
                    continue;
                }
                tracked.apply(version, ());
                changed = true;
            }
            if changed && trigger != Trigger::Start {
                entry.follower.reload();
            }
        }
    }
}

/// The versions of `plan`'s files in `dir`.
pub(super) fn observe_all(dir: &Path, plan: &[&'static [&'static str]]) -> Vec<Vec<Version>> {
    plan.iter()
        .map(|files| files.iter().map(|file| observe(&dir.join(file))).collect())
        .collect()
}
