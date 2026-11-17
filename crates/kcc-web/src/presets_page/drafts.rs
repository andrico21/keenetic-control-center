//! New presets' sources, held in memory between reading the source and saving the
//! preset: at most [`KEPT`], each for [`LIFETIME`] seconds, for the account that read it.
//!
//! A draft holds the whole source configuration, so it never reaches the disk: a restart
//! forgets it, and the account reads the source again.

use alloc::sync::Arc;
use std::sync::{Mutex, MutexGuard, PoisonError};

use kcc_migrate::presets::model::{PresetSource, PresetSourceKind};
use secrecy::SecretString;

use crate::wizard::source::Source;

/// Drafts kept in memory; the oldest one is forgotten first.
const KEPT: usize = 32;

/// How long a draft is kept, in seconds.
const LIFETIME: u64 = 60 * 60;

/// A new preset's source, read and checked.
pub(super) struct Draft {
    /// The account that read it.
    owner: String,
    /// Unix time it was read.
    read_at: u64,
    /// Where it came from.
    source: Source,
    /// Its model and firmware.
    facts: (String, String),
    /// The source configuration.
    text: SecretString,
}

impl Draft {
    /// The source `source` read by `owner` at `read_at`: its `(model, firmware)` and text.
    pub(super) fn new(
        (owner, read_at): (String, u64),
        source: Source,
        facts: (String, String),
        text: SecretString,
    ) -> Self {
        Self {
            owner,
            read_at,
            source,
            facts,
            text,
        }
    }

    /// Where it came from.
    pub(super) const fn source(&self) -> &Source {
        &self.source
    }

    /// The source's model.
    pub(super) fn model(&self) -> &str {
        &self.facts.0
    }

    /// The source's firmware version.
    pub(super) fn firmware(&self) -> &str {
        &self.facts.1
    }

    /// The source configuration.
    pub(super) const fn text(&self) -> &SecretString {
        &self.text
    }

    /// The facts a preset of this source records.
    pub(super) fn preset_source(&self) -> PresetSource {
        let (kind, router) = match &self.source {
            Source::Router { router } => (PresetSourceKind::Router, Some(router.clone())),
            Source::Backup { router, name: _ } => (PresetSourceKind::Backup, Some(router.clone())),
            Source::File { name: _ } => (PresetSourceKind::File, None),
        };
        PresetSource::new(
            kind,
            router,
            self.facts.0.clone(),
            self.facts.1.clone(),
            self.read_at,
        )
    }
}

/// Every draft of one Web UI.
#[derive(Default)]
pub(super) struct Drafts {
    /// Draft id and draft, oldest first.
    entries: Mutex<Vec<(String, Arc<Draft>)>>,
}

impl Drafts {
    /// Keeps `draft` as `id`, forgetting expired drafts and, past [`KEPT`], the oldest.
    pub(super) fn keep(&self, id: String, draft: Draft, now: u64) {
        let mut entries = lock(&self.entries);
        entries.retain(|(_, kept)| kept.read_at.saturating_add(LIFETIME) >= now);
        if entries.len() >= KEPT {
            drop(entries.remove(0));
        }
        entries.push((id, Arc::new(draft)));
    }

    /// The draft `id` of `owner`, while it is kept.
    pub(super) fn get(&self, id: &str, owner: &str, now: u64) -> Option<Arc<Draft>> {
        lock(&self.entries)
            .iter()
            .find(|(known, draft)| {
                known == id && draft.owner == owner && draft.read_at.saturating_add(LIFETIME) >= now
            })
            .map(|(_, draft)| Arc::clone(draft))
    }

    /// Forgets the draft `id`.
    pub(super) fn remove(&self, id: &str) {
        lock(&self.entries).retain(|(known, _)| known != id);
    }
}

/// A lock whose holder cannot leave the data half-written, so a poisoned lock is used
/// as is.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
