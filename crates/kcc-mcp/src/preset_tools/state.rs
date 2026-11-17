//! The encrypted preset store and this process's transient (never stored) presets.

use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_migrate::presets::{
    model::Preset,
    store::{PresetError, PresetStore},
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::{McpFailure, support::blocking};

/// One transient preset and the identity that captured it.
#[derive(Debug)]
struct Transient {
    /// Capturing identity; nobody else may use the copy.
    owner: String,
    /// The captured preset, secrets kept only in memory.
    preset: Preset,
}

/// Preset services of one MCP handler.
#[derive(Debug, Default)]
pub(crate) struct Presets {
    /// Encrypted store; absent when the host did not attach one.
    store: Option<PresetStore>,
    /// Transient presets by id.
    transients: Mutex<BTreeMap<String, Transient>>,
    /// Sequence making transient ids unique within the process.
    sequence: AtomicU64,
}

impl Presets {
    /// Wraps the encrypted store.
    pub(crate) fn new(store: PresetStore) -> Self {
        Self {
            store: Some(store),
            ..Self::default()
        }
    }

    /// The encrypted store.
    pub(crate) fn store(&self) -> Result<&PresetStore, McpFailure> {
        self.store.as_ref().ok_or_else(|| {
            tracing::error!("MCP preset store is not configured");
            McpFailure::Internal
        })
    }

    /// Runs `work` on the encrypted store on the blocking pool: the store reads, writes
    /// and seals files.
    ///
    /// # Errors
    ///
    /// Returns [`McpFailure::Internal`] without a store or when the task did not finish;
    /// the store's own error is the inner result.
    // NOT cancel-safe: dropped, `work` still runs to its end on the blocking pool.
    pub(crate) async fn stored<T, W>(
        self: &Arc<Self>,
        work: W,
    ) -> Result<Result<T, PresetError>, McpFailure>
    where
        W: FnOnce(&PresetStore) -> Result<T, PresetError> + Send + 'static,
        T: Send + 'static,
    {
        let presets = Arc::clone(self);
        blocking::run(move || presets.store().map(work)).await?
    }

    /// A fresh transient id.
    pub(crate) fn transient_id(&self) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        format!("transient-{nanos:x}-{sequence}")
    }

    /// Keeps a transient preset for `owner`.
    pub(crate) async fn keep(&self, owner: String, preset: Preset) {
        let id = preset.id.clone();
        drop(
            self.transients
                .lock()
                .await
                .insert(id, Transient { owner, preset }),
        );
    }

    /// The transient preset `id`, if one exists; another identity's copy is forbidden.
    pub(crate) async fn transient(
        &self,
        owner: &str,
        id: &str,
    ) -> Result<Option<Preset>, McpFailure> {
        match self.transients.lock().await.get(id) {
            None => Ok(None),
            Some(entry) if entry.owner == owner => Ok(Some(entry.preset.clone())),
            Some(_) => Err(McpFailure::Forbidden),
        }
    }

    /// Removes the transient preset `id`; returns whether one was removed.
    pub(crate) async fn forget(&self, owner: &str, id: &str) -> Result<bool, McpFailure> {
        let mut entries = self.transients.lock().await;
        match entries.get(id) {
            None => Ok(false),
            Some(entry) if entry.owner == owner => Ok(entries.remove(id).is_some()),
            Some(_) => Err(McpFailure::Forbidden),
        }
    }

    /// Redacted views of `owner`'s transient presets.
    pub(crate) async fn transient_views(&self, owner: &str) -> Vec<Value> {
        self.transients
            .lock()
            .await
            .values()
            .filter(|entry| entry.owner == owner)
            .map(|entry| view(&entry.preset, true))
            .collect()
    }
}

/// The redacted view of a preset; MCP never reveals secret values.
pub(crate) fn view(preset: &Preset, transient: bool) -> Value {
    let redacted = preset.redacted();
    json!({
        "id": redacted.id,
        "name": redacted.name,
        "description": redacted.description,
        "groups": redacted.groups,
        "source": redacted.source,
        "created_by": redacted.created_by,
        "transient": transient,
        "lines": redacted.lines.iter().map(ToString::to_string).collect::<Vec<_>>()
    })
}

/// Maps a preset store failure.
pub(crate) fn map_preset(error: &PresetError) -> McpFailure {
    tracing::warn!(error = ?error, "MCP preset operation failed");
    match error {
        PresetError::Forbidden => McpFailure::Forbidden,
        PresetError::InvalidId | PresetError::NotFound | PresetError::Groups(_) => {
            McpFailure::InvalidArguments
        }
        PresetError::Malformed
        | PresetError::State(_)
        | PresetError::Crypto(_)
        | PresetError::Io(_)
        | _ => McpFailure::Internal,
    }
}
