//! Serialized, tamper-evident audit logging with size-based rotation.

use core::fmt;
extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::time::Duration;
use std::{
    fs::{self, File},
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, error::Category};
use sha2::{Digest as _, Sha256};
use tokio::{
    sync::{mpsc, watch},
    time::timeout,
};

use crate::{
    accounts::{Clock, SystemClock},
    persist::{StateError, StateLock, StateStore, io_error, open_private_append_file},
};

mod append_lock;
pub mod receipt;
mod writer;

use append_lock::RetryPolicy;
use receipt::{AUDIT_WAIT, Pending, Reply};

/// Default audit rotation threshold: 50 MiB.
pub const DEFAULT_ROTATE_BYTES: u64 = 50 * 1024 * 1024;
/// Active audit file name.
pub const AUDIT_FILE_NAME: &str = "audit.jsonl";
/// Default audit retention: 365 days.
pub const DEFAULT_RETENTION: Duration = Duration::from_hours(365 * 24);
/// All-zero hash before the first audit entry.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Audit rotation, retention, and time-source policy.
#[derive(Clone)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name identifies this policy at call sites"
)]
pub struct AuditPolicy {
    /// Active-file rotation threshold.
    rotate_bytes: u64,
    /// Maximum age of complete rotated files.
    retention: Duration,
    /// Unix timestamp source used by retention.
    clock: Arc<dyn Clock>,
    /// Bounded cross-process append-lock retry policy.
    append_lock_retry: RetryPolicy,
}

impl fmt::Debug for AuditPolicy {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditPolicy")
            .field("rotate_bytes", &self.rotate_bytes)
            .field("retention", &self.retention)
            .finish_non_exhaustive()
    }
}

impl Default for AuditPolicy {
    #[inline]
    fn default() -> Self {
        Self {
            rotate_bytes: DEFAULT_ROTATE_BYTES,
            retention: DEFAULT_RETENTION,
            clock: Arc::new(SystemClock),
            append_lock_retry: RetryPolicy::PRODUCTION,
        }
    }
}

impl AuditPolicy {
    /// Sets the rotation threshold.
    #[inline]
    #[must_use]
    pub const fn with_rotate_bytes(mut self, rotate_bytes: u64) -> Self {
        self.rotate_bytes = rotate_bytes;
        self
    }

    /// Sets how long complete rotated files are retained.
    #[inline]
    #[must_use]
    pub const fn with_retention(mut self, retention: Duration) -> Self {
        self.retention = retention;
        self
    }

    /// Sets the Unix clock used by retention.
    #[inline]
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Sets the backoff of each round of append-lock attempts, from `initial` up to
    /// `maximum` between attempts; tests use short delays.
    #[inline]
    #[must_use]
    pub const fn with_append_lock_backoff(mut self, initial: Duration, maximum: Duration) -> Self {
        self.append_lock_retry = RetryPolicy::backoff(initial, maximum);
        self
    }

    /// Sets deterministic append-lock retry parameters for unit tests.
    #[cfg(test)]
    const fn with_append_lock_retry(mut self, retry: RetryPolicy) -> Self {
        self.append_lock_retry = retry;
        self
    }
}

/// Audit actor kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ActorKind {
    /// Web UI actor.
    Web,
    /// MCP actor.
    Mcp,
    /// Command-line actor.
    Cli,
    /// Internal system actor.
    System,
}

/// Principal recorded for an audited action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Actor {
    /// Front-end kind.
    pub kind: ActorKind,
    /// Stable principal identifier.
    pub id: String,
}

impl Actor {
    /// Longest recorded principal identifier, in bytes.
    pub const MAX_ID_BYTES: usize = 64;

    /// Creates an audit principal, cutting `id` to [`Self::MAX_ID_BYTES`] at a char
    /// boundary.
    #[inline]
    #[must_use]
    pub fn new(kind: ActorKind, mut id: String) -> Self {
        id.truncate(id.floor_char_boundary(Self::MAX_ID_BYTES));
        Self { kind, id }
    }
}

/// How an attempted action ended without doing what it was asked to: the same outcome
/// and parameter shape on every surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attempt {
    /// The principal lacks the permission or router scope; outcome `forbidden`.
    Forbidden,
    /// Refused before anything was sent, such as a missing confirmation; outcome
    /// `refused`.
    Refused {
        /// Stable reason code, such as `confirm_required`.
        reason: &'static str,
    },
    /// Started and failed; outcome `failed`.
    Failed {
        /// Stable error code, such as `router`.
        error: &'static str,
        /// Whether a recovery timer kcc armed may still be armed.
        fail_safe_armed: bool,
    },
}

/// Caller-supplied audit event before sequence and chain hashes are assigned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is clearer than Event at call sites"
)]
pub struct AuditEvent {
    /// Unix timestamp in seconds.
    pub ts: u64,
    /// Acting principal.
    pub actor: Actor,
    /// Router name, when the action targets one.
    pub router: Option<String>,
    /// Stable action identifier.
    pub action: String,
    /// Action target.
    pub target: Option<String>,
    /// Already-redacted structured parameters.
    pub params_redacted: Value,
    /// Stable outcome identifier.
    pub outcome: String,
    /// Correlation request identifier.
    pub request_id: String,
}

impl AuditEvent {
    /// Creates an event identity with optional fields and outcome metadata
    /// absent until explicitly supplied.
    #[inline]
    #[must_use]
    pub const fn new(ts: u64, actor: Actor, action: String) -> Self {
        Self {
            ts,
            actor,
            router: None,
            action,
            target: None,
            params_redacted: Value::Null,
            outcome: String::new(),
            request_id: String::new(),
        }
    }

    /// The event of `attempt`: outcome `forbidden`, `refused` or `failed`, with params
    /// `{"reason": ..}` or `{"error": ..}`, plus `"fail_safe_armed": true` only when a
    /// recovery timer may still be armed. The request id is still unset.
    #[inline]
    #[must_use]
    pub fn attempt(
        ts: u64,
        actor: Actor,
        action: String,
        router: Option<String>,
        attempt: Attempt,
    ) -> Self {
        let (outcome, params) = match attempt {
            Attempt::Forbidden => ("forbidden", serde_json::json!({ "reason": "forbidden" })),
            Attempt::Refused { reason } => ("refused", serde_json::json!({ "reason": reason })),
            Attempt::Failed {
                error,
                fail_safe_armed: true,
            } => (
                "failed",
                serde_json::json!({ "error": error, "fail_safe_armed": true }),
            ),
            Attempt::Failed {
                error,
                fail_safe_armed: false,
            } => ("failed", serde_json::json!({ "error": error })),
        };
        Self {
            router,
            params_redacted: params,
            outcome: outcome.to_owned(),
            ..Self::new(ts, actor, action)
        }
    }

    /// Sets the correlation request identifier.
    #[inline]
    #[must_use]
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = request_id;
        self
    }

    /// Sets already-redacted structured parameters.
    #[inline]
    #[must_use]
    pub fn with_params(mut self, params_redacted: Value) -> Self {
        self.params_redacted = params_redacted;
        self
    }

    /// Sets the stable outcome identifier and correlation request identifier.
    #[inline]
    #[must_use]
    pub fn with_result(mut self, outcome: String, request_id: String) -> Self {
        self.outcome = outcome;
        self.request_id = request_id;
        self
    }

    /// Sets the router name.
    #[inline]
    #[must_use]
    pub fn with_router(mut self, router: String) -> Self {
        self.router = Some(router);
        self
    }

    /// Sets the action target.
    #[inline]
    #[must_use]
    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }
}

/// One persisted hash-chained audit entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is clearer than Entry at call sites"
)]
pub struct AuditEntry {
    /// Unix timestamp in seconds.
    pub ts: u64,
    /// Monotonically increasing sequence number.
    pub seq: u64,
    /// Acting principal.
    pub actor: Actor,
    /// Router name, when present.
    pub router: Option<String>,
    /// Stable action identifier.
    pub action: String,
    /// Action target.
    pub target: Option<String>,
    /// Structured parameters after redaction.
    pub params_redacted: Value,
    /// Stable outcome identifier.
    pub outcome: String,
    /// Correlation request identifier.
    pub request_id: String,
    /// Previous entry hash, including across rotated files.
    pub prev_hash: String,
    /// SHA-256 chain hash of the previous hash and canonical entry body.
    pub hash: String,
}

/// Audit errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is clearer than Error at call sites"
)]
pub enum AuditError {
    /// State storage or file I/O failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// JSON serialization or parsing failed.
    #[error("audit JSON is invalid: {reason}")]
    Json {
        /// Generic parse/serialization reason without sensitive event values.
        reason: String,
    },
    /// The chain failed at an exact sequence number.
    #[error("audit hash chain verification failed at sequence {seq}")]
    Chain {
        /// First invalid sequence number.
        seq: u64,
    },
    /// Audit writer task is no longer available.
    #[error("audit writer is unavailable")]
    WriterUnavailable,
    /// A parameter key indicates a secret-bearing value.
    #[error("audit parameters contain forbidden secret key {key:?}")]
    SecretParameter {
        /// Rejected parameter key.
        key: String,
    },
    /// Another process held the audit append lock beyond one bounded round of attempts;
    /// the writer keeps the entry queued and starts another round.
    #[error("audit append lock remained busy")]
    AppendLockTimeout,
    /// The caller stopped waiting; the entry stays queued and is written once the append
    /// lock is free.
    #[error("audit entry is still queued")]
    Pending,
}

/// A cloneable handle to the one audit writer task.
#[derive(Clone)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is clearer than Log at call sites"
)]
pub struct AuditLog {
    /// Command channel consumed by exactly one task.
    sender: mpsc::Sender<Command>,
    /// Entries submitted and not yet written.
    queued: Arc<watch::Sender<usize>>,
}

impl fmt::Debug for AuditLog {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditLog").finish_non_exhaustive()
    }
}

/// Writer command carrying an acknowledgement channel.
#[derive(Debug)]
enum Command {
    /// Append one event.
    Append {
        /// Validated event.
        event: AuditEvent,
        /// The writer's answer.
        reply: watch::Sender<Reply>,
    },
}

impl AuditLog {
    /// Starts the single writer task for a state directory.
    ///
    /// # Errors
    ///
    /// Returns an I/O, parse, or chain error while recovering the chain tail.
    #[inline]
    pub fn spawn(store: &StateStore) -> Result<Self, AuditError> {
        Self::spawn_with_policy(store, AuditPolicy::default())
    }

    /// Starts the writer with a custom rotation limit, primarily for bounded
    /// tests. Production callers use [`Self::spawn`].
    ///
    /// # Errors
    ///
    /// Returns an I/O, parse, or chain error while recovering the chain tail.
    #[inline]
    pub fn spawn_with_limit(store: &StateStore, rotate_bytes: u64) -> Result<Self, AuditError> {
        Self::spawn_with_policy(
            store,
            AuditPolicy::default().with_rotate_bytes(rotate_bytes),
        )
    }

    /// Starts the writer with an explicit rotation and retention policy.
    ///
    /// # Errors
    ///
    /// Returns an I/O, parse, or chain error while recovering the chain tail.
    #[inline]
    pub fn spawn_with_policy(store: &StateStore, policy: AuditPolicy) -> Result<Self, AuditError> {
        let files = audit_files(store.dir())?;
        let verified = verify_files(&files)?;
        let (next_seq, previous_hash) = verified.last().map_or_else(
            || (1, GENESIS_HASH.to_owned()),
            |entry| (entry.seq.saturating_add(1), entry.hash.clone()),
        );
        let path = store.dir().join(AUDIT_FILE_NAME);
        let file = open_private_append_file(&path)?;
        let (sender, receiver) = mpsc::channel(128);
        let state = WriterState {
            store: store.clone(),
            dir: store.dir().to_owned(),
            file,
            current_bytes: fs::metadata(&path).map_or(0, |metadata| metadata.len()),
            rotate_bytes: policy.rotate_bytes,
            retention: policy.retention,
            clock: policy.clock,
            next_seq,
            previous_hash,
            append_lock_retry: policy.append_lock_retry,
        };
        let queued = Arc::new(watch::Sender::new(0));
        drop(tokio::spawn(writer::writer_task(
            receiver,
            state,
            Arc::clone(&queued),
        )));
        Ok(Self { sender, queued })
    }

    /// Queues one audit event after rejecting secret-shaped parameter keys, and returns
    /// the handle of the queued entry without waiting for it to be written.
    ///
    /// # Errors
    ///
    /// Returns a validation error, or [`AuditError::WriterUnavailable`] after a fatal
    /// writer failure.
    // cancel-safe: cancelled while waiting for a channel slot nothing is queued; the slot
    // taken, the entry is queued without another await.
    #[inline]
    pub async fn submit(&self, event: AuditEvent) -> Result<Pending, AuditError> {
        reject_secret_parameters(&event.params_redacted)?;
        let slot = self
            .sender
            .reserve()
            .await
            .map_err(|_error| AuditError::WriterUnavailable)?;
        let (reply, answer) = watch::channel(Reply::Queued);
        self.queued
            .send_modify(|count| *count = count.saturating_add(1));
        slot.send(Command::Append { event, reply });
        Ok(Pending::new(answer))
    }

    /// Waits at most `limit` for every queued entry to be written, and returns how many
    /// were still queued then, or lost with a writer that failed.
    // cancel-safe: waiting only observes the writer's progress.
    #[inline]
    pub async fn flush(&self, limit: Duration) -> usize {
        let mut progress = self.queued.subscribe();
        let sender = &self.sender;
        let drained = progress.wait_for(|count| *count == 0 || sender.is_closed());
        drop(timeout(limit, drained).await);
        *self.queued.borrow()
    }

    /// Appends one audit event after rejecting secret-shaped parameter keys, waiting at
    /// most [`AUDIT_WAIT`] for it to be written.
    ///
    /// # Errors
    ///
    /// Returns a validation error, [`AuditError::Pending`] when the entry is still
    /// queued at the deadline (it is written later), or
    /// [`AuditError::WriterUnavailable`] after a fatal writer failure.
    #[inline]
    // NOT cancel-safe: once queued, the writer appends the event even if the caller stops awaiting;
    // cancelled earlier, the event is dropped unwritten.
    pub async fn append(&self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        self.submit(event).await?.wait(AUDIT_WAIT).await
    }

    /// Whether the audit writer task is still accepting commands.
    #[inline]
    #[must_use]
    pub fn is_alive(&self) -> bool {
        !self.sender.is_closed()
    }

    /// Refuses work that would require an audit receipt when the writer is unavailable.
    ///
    /// # Errors
    /// Returns [`AuditError::WriterUnavailable`] after a fatal writer failure.
    #[inline]
    pub fn require_alive(&self) -> Result<(), AuditError> {
        self.is_alive()
            .then_some(())
            .ok_or(AuditError::WriterUnavailable)
    }

    /// Waits until a fatal writer failure closes the command channel.
    // cancel-safe: observing channel closure has no side effects.
    #[inline]
    pub async fn closed(&self) {
        self.sender.closed().await;
    }
}

/// Mutable state owned exclusively by the writer task.
#[derive(Debug)]
struct WriterState {
    /// State store used to coordinate appenders in other processes.
    store: StateStore,
    /// Audit directory.
    dir: PathBuf,
    /// Active append handle.
    file: File,
    /// Current active-file size.
    current_bytes: u64,
    /// Rotation threshold.
    rotate_bytes: u64,
    /// Next sequence number.
    next_seq: u64,
    /// Last chain hash.
    previous_hash: String,
    /// Maximum age of complete rotated files.
    retention: Duration,
    /// Timestamp source for retention decisions.
    clock: Arc<dyn Clock>,
    /// Bounded cross-process append-lock retry policy.
    append_lock_retry: RetryPolicy,
}

impl WriterState {
    /// Hashes, rotates if needed, appends, syncs, then advances chain state.
    ///
    /// # Errors
    ///
    /// Returns serialization, I/O, or rotation errors.
    fn append_locked(
        &mut self,
        event: AuditEvent,
        _lock: &StateLock,
    ) -> Result<AuditEntry, AuditError> {
        let files = audit_files(&self.dir)?;
        let verified = verify_files(&files)?;
        let (next_seq, previous_hash) = verified.last().map_or_else(
            || (1, GENESIS_HASH.to_owned()),
            |entry| (entry.seq.saturating_add(1), entry.hash.clone()),
        );
        let active = self.dir.join(AUDIT_FILE_NAME);
        self.file = open_private_append_file(&active)?;
        self.current_bytes = fs::metadata(&active).map_or(0, |metadata| metadata.len());
        self.next_seq = next_seq;
        self.previous_hash = previous_hash;
        let mut entry = AuditEntry {
            ts: event.ts,
            seq: self.next_seq,
            actor: event.actor,
            router: event.router,
            action: event.action,
            target: event.target,
            params_redacted: event.params_redacted,
            outcome: event.outcome,
            request_id: event.request_id,
            prev_hash: self.previous_hash.clone(),
            hash: String::new(),
        };
        entry.hash = calculate_hash(&entry)?;
        let mut bytes = serde_json::to_vec(&entry).map_err(|error| json_error(&error))?;
        bytes.push(b'\n');
        let byte_count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.current_bytes > 0
            && self.current_bytes.saturating_add(byte_count) > self.rotate_bytes
        {
            self.rotate()?;
            self.prune_rotated()?;
        }
        self.file
            .write_all(&bytes)
            .and_then(|()| self.file.sync_data())
            .map_err(|error| io_error(&self.dir.join(AUDIT_FILE_NAME), error))?;
        self.current_bytes = self.current_bytes.saturating_add(byte_count);
        self.next_seq = self.next_seq.saturating_add(1);
        self.previous_hash.clone_from(&entry.hash);
        Ok(entry)
    }

    /// Renames the active file to a sequence-addressed archive and opens a new
    /// owner-only active file. Chain state deliberately remains unchanged.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if syncing, renaming, or reopening fails.
    fn rotate(&mut self) -> Result<(), AuditError> {
        let active = self.dir.join(AUDIT_FILE_NAME);
        let archive = self.dir.join(format!(
            "audit-{:020}.jsonl",
            self.next_seq.saturating_sub(1)
        ));
        self.file
            .sync_all()
            .map_err(|error| io_error(&active, error))?;
        fs::rename(&active, &archive).map_err(|error| io_error(&archive, error))?;
        self.file = open_private_append_file(&active)?;
        self.current_bytes = 0;
        Ok(())
    }

    /// Removes the oldest run of rotated files whose newest entry predates the cutoff.
    ///
    /// # Errors
    ///
    /// Returns an I/O or JSON error while inspecting or removing an archive.
    fn prune_rotated(&self) -> Result<(), AuditError> {
        let retention = self.retention.as_secs();
        if retention == 0 {
            return Ok(());
        }
        let cutoff = self.clock.unix_seconds().saturating_sub(retention);
        for path in rotated_files(&self.dir)? {
            let entries = read_file(&path)?;
            if entries.last().is_none_or(|entry| entry.ts >= cutoff) {
                break;
            }
            fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
        }
        Ok(())
    }
}

/// Verifies every rotated file and the active file as one continuous chain.
///
/// # Errors
///
/// Returns the first invalid sequence in [`AuditError::Chain`], or an I/O/JSON
/// error if a line cannot be read or decoded.
#[inline]
pub fn verify_chain(dir: &Path) -> Result<Vec<AuditEntry>, AuditError> {
    verify_files(&audit_files(dir)?)
}

/// Reads every entry of the rotated files and the active file, in chain order, without
/// verifying the chain; for showing a log whose chain [`verify_chain`] rejects.
///
/// # Errors
///
/// Returns an I/O or JSON error if a file or line cannot be read or decoded.
#[inline]
pub fn read_entries(dir: &Path) -> Result<Vec<AuditEntry>, AuditError> {
    let mut entries = Vec::new();
    for path in audit_files(dir)? {
        let file = File::open(&path).map_err(|error| io_error(&path, error))?;
        for read_result in BufReader::new(file).lines() {
            let line = read_result.map_err(|error| io_error(&path, error))?;
            if !line.is_empty() {
                entries.push(serde_json::from_str(&line).map_err(|error| json_error(&error))?);
            }
        }
    }
    Ok(entries)
}

/// Discovers rotated files in sequence order, followed by the active file.
///
/// # Errors
///
/// Returns an I/O error when the audit directory cannot be listed.
fn audit_files(dir: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut rotated = rotated_files(dir)?;
    let active = dir.join(AUDIT_FILE_NAME);
    if active.exists() {
        rotated.push(active);
    }
    Ok(rotated)
}

/// Discovers rotated audit files in sequence order.
///
/// # Errors
///
/// Returns an I/O error when the audit directory cannot be listed.
fn rotated_files(dir: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut rotated = Vec::new();
    for listed in fs::read_dir(dir).map_err(|error| io_error(dir, error))? {
        let entry = listed.map_err(|error| io_error(dir, error))?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name.starts_with("audit-")
            && Path::new(name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("jsonl"))
        {
            rotated.push(entry.path());
        }
    }
    rotated.sort();
    Ok(rotated)
}

/// Verifies a caller-ordered list of chain files.
///
/// # Errors
///
/// Returns the first I/O, JSON, or chain validation error.
fn verify_files(files: &[PathBuf]) -> Result<Vec<AuditEntry>, AuditError> {
    let mut entries = Vec::new();
    let mut expected_sequence = None;
    let mut previous_hash = None;
    for path in files {
        let file = File::open(path).map_err(|error| io_error(path, error))?;
        for read_result in BufReader::new(file).lines() {
            let line = read_result.map_err(|error| io_error(path, error))?;
            if line.is_empty() {
                continue;
            }
            let entry: AuditEntry =
                serde_json::from_str(&line).map_err(|error| json_error(&error))?;
            if expected_sequence.is_some_and(|expected| entry.seq != expected)
                || previous_hash
                    .as_ref()
                    .is_some_and(|expected| entry.prev_hash != *expected)
            {
                return Err(AuditError::Chain { seq: entry.seq });
            }
            if entries.is_empty() && entry.seq == 1 && entry.prev_hash != GENESIS_HASH {
                return Err(AuditError::Chain { seq: entry.seq });
            }
            let calculated = calculate_hash(&entry)?;
            if entry.hash != calculated {
                return Err(AuditError::Chain { seq: entry.seq });
            }
            expected_sequence = Some(entry.seq.saturating_add(1));
            previous_hash = Some(entry.hash.clone());
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Reads one audit archive without validating its predecessor.
///
/// # Errors
///
/// Returns an I/O or JSON error when a line cannot be decoded.
fn read_file(path: &Path) -> Result<Vec<AuditEntry>, AuditError> {
    let file = File::open(path).map_err(|error| io_error(path, error))?;
    let mut entries = Vec::new();
    for read_result in BufReader::new(file).lines() {
        let line = read_result.map_err(|error| io_error(path, error))?;
        if !line.is_empty() {
            entries.push(serde_json::from_str(&line).map_err(|error| json_error(&error))?);
        }
    }
    Ok(entries)
}

/// Calculates `sha256(prev_hash || canonical_json(entry_without_hash))`.
///
/// # Errors
///
/// Returns a canonical serialization or hash encoding error.
fn calculate_hash(entry: &AuditEntry) -> Result<String, AuditError> {
    let canonical = canonical_entry_without_hash(entry)?;
    let mut digest = Sha256::new();
    digest.update(entry.prev_hash.as_bytes());
    digest.update(canonical);
    let bytes = digest.finalize();
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use core::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_error| AuditError::Json {
            reason: "hash encoding failed".to_owned(),
        })?;
    }
    Ok(encoded)
}

/// Serializes a fixed-order map so hash bytes are stable across processes.
///
/// # Errors
///
/// Returns an error if one of the entry fields cannot be serialized.
fn canonical_entry_without_hash(entry: &AuditEntry) -> Result<Vec<u8>, AuditError> {
    let mut fields = BTreeMap::new();
    drop(fields.insert(
        "action",
        serde_json::to_value(&entry.action).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert(
        "actor",
        serde_json::to_value(&entry.actor).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert(
        "outcome",
        serde_json::to_value(&entry.outcome).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert("params_redacted", entry.params_redacted.clone()));
    drop(fields.insert("prev_hash", Value::from(entry.prev_hash.clone())));
    drop(fields.insert("request_id", Value::from(entry.request_id.clone())));
    drop(fields.insert(
        "router",
        serde_json::to_value(&entry.router).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert("seq", Value::from(entry.seq)));
    drop(fields.insert(
        "target",
        serde_json::to_value(&entry.target).map_err(|error| json_error(&error))?,
    ));
    drop(fields.insert("ts", Value::from(entry.ts)));
    serde_json::to_vec(&fields).map_err(|error| json_error(&error))
}

/// Rejects parameter names likely to contain raw credentials. Callers must
/// rename safely transformed values (for example `password_present`).
///
/// # Errors
///
/// Returns [`AuditError::SecretParameter`] for a forbidden key at any depth.
fn reject_secret_parameters(value: &Value) -> Result<(), AuditError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let lowered = key.to_ascii_lowercase();
                if ["password", "passwd", "api_key", "token", "secret"]
                    .iter()
                    .any(|needle| lowered.contains(needle))
                {
                    return Err(AuditError::SecretParameter { key: key.clone() });
                }
                reject_secret_parameters(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                reject_secret_parameters(nested)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

/// Converts serde errors without embedding an event's potentially sensitive
/// source text in the error surface.
fn json_error(error: &serde_json::Error) -> AuditError {
    let category = match error.classify() {
        Category::Io => "I/O",
        Category::Syntax => "syntax",
        Category::Data => "data",
        Category::Eof => "end of input",
    };
    AuditError::Json {
        reason: format!(
            "{category} at line {}, column {}",
            error.line(),
            error.column()
        ),
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
    use core::{error::Error, time::Duration};
    use std::fs;

    use serde_json::json;
    use tempfile::TempDir;
    use tokio::{task::yield_now, time};

    use super::{
        Actor, ActorKind, Attempt, AuditEntry, AuditError, AuditEvent, AuditLog, AuditPolicy,
        GENESIS_HASH, RetryPolicy, calculate_hash, verify_files,
    };
    use crate::persist::StateStore;

    fn entry(seq: u64, prev_hash: String) -> Result<AuditEntry, AuditError> {
        let mut entry = AuditEntry {
            ts: 1_700_000_000,
            seq,
            actor: Actor::new(ActorKind::Web, "alice".to_owned()),
            router: None,
            action: "router.read".to_owned(),
            target: None,
            params_redacted: json!({}),
            outcome: "ok".to_owned(),
            request_id: "request-1".to_owned(),
            prev_hash,
            hash: String::new(),
        };
        entry.hash = calculate_hash(&entry)?;
        Ok(entry)
    }

    fn verify_single(entry: &AuditEntry) -> Result<Vec<AuditEntry>, Box<dyn Error>> {
        let temp = TempDir::new()?;
        let path = temp.path().join("audit.jsonl");
        fs::write(&path, format!("{}\n", serde_json::to_string(entry)?))?;
        Ok(verify_files(&[path])?)
    }

    fn event(sequence: u64) -> AuditEvent {
        AuditEvent::new(
            sequence,
            Actor::new(ActorKind::System, "audit-test".to_owned()),
            "test.append".to_owned(),
        )
        .with_result("success".to_owned(), format!("request-{sequence}"))
    }

    async fn settle() {
        for _attempt in 0_u8..8_u8 {
            yield_now().await;
        }
    }

    #[test]
    fn first_entry_at_seq_one_must_start_at_genesis() -> Result<(), Box<dyn Error>> {
        let forged = entry(1, "ab".repeat(32))?;
        let result = verify_single(&forged);
        assert!(
            matches!(
                result
                    .as_ref()
                    .err()
                    .and_then(|error| error.downcast_ref::<AuditError>()),
                Some(AuditError::Chain { seq: 1 })
            ),
            "forged genesis must fail at seq 1, got {result:?}"
        );
        assert_eq!(verify_single(&entry(1, GENESIS_HASH.to_owned())?)?.len(), 1);
        assert_eq!(verify_single(&entry(2, "ab".repeat(32))?)?.len(), 1);
        Ok(())
    }

    /// SEC1-02: an actor id is bounded to 64 bytes, cut at a char boundary, so no
    /// caller can write an unbounded principal into the audit log.
    #[test]
    fn actor_id_is_truncated_to_64_bytes_at_a_char_boundary() {
        let straddling = format!("{}\u{e9}tail", "a".repeat(63));
        assert_eq!(
            Actor::new(ActorKind::Web, straddling).id,
            "a".repeat(63),
            "a two-byte char across byte 64 is dropped whole"
        );
        let huge = Actor::new(ActorKind::Web, "b".repeat(1024 * 1024));
        assert_eq!(
            huge.id,
            "b".repeat(64),
            "a 1 MiB id keeps its first 64 bytes"
        );
        let short = Actor::new(ActorKind::Cli, "alice".to_owned());
        assert_eq!(short.id, "alice", "a short id is unchanged");
    }

    #[test]
    fn attempts_share_one_outcome_and_params_shape() {
        let armed = Attempt::Failed {
            error: "router",
            fail_safe_armed: true,
        };
        let unarmed = Attempt::Failed {
            error: "router",
            fail_safe_armed: false,
        };
        let refused = Attempt::Refused {
            reason: "confirm_required",
        };
        for (attempt, outcome, params) in [
            (
                Attempt::Forbidden,
                "forbidden",
                json!({"reason": "forbidden"}),
            ),
            (refused, "refused", json!({"reason": "confirm_required"})),
            (
                armed,
                "failed",
                json!({"error": "router", "fail_safe_armed": true}),
            ),
            (unarmed, "failed", json!({"error": "router"})),
        ] {
            let event = AuditEvent::attempt(
                7,
                Actor::new(ActorKind::Cli, "tester".to_owned()),
                "cli.change".to_owned(),
                Some("lab-1".to_owned()),
                attempt,
            );
            assert_eq!(event.outcome, outcome, "{attempt:?}");
            assert_eq!(event.params_redacted, params, "{attempt:?}");
            assert_eq!(event.router.as_deref(), Some("lab-1"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn append_waits_beyond_the_old_contention_window() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let held = state.try_lock(super::AUDIT_FILE_NAME)?;
        let retry = RetryPolicy::testing(6, Duration::from_secs(1), Duration::from_secs(1));
        let audit = AuditLog::spawn_with_policy(
            &state,
            AuditPolicy::default().with_append_lock_retry(retry),
        )?;
        let pending = tokio::spawn({
            let writer = audit.clone();
            async move { writer.append(event(1)).await }
        });
        settle().await;

        time::advance(Duration::from_millis(2_500)).await;
        settle().await;
        assert!(
            !pending.is_finished(),
            "the append still waits after two seconds"
        );
        drop(held);
        time::advance(Duration::from_secs(2)).await;

        drop(pending.await??);
        assert!(audit.is_alive());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_lock_timeout_keeps_the_entry_queued_and_the_writer_alive()
    -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let held = state.try_lock(super::AUDIT_FILE_NAME)?;
        let retry = RetryPolicy::testing(2, Duration::from_millis(1), Duration::from_millis(1));
        let audit = AuditLog::spawn_with_policy(
            &state,
            AuditPolicy::default().with_append_lock_retry(retry),
        )?;
        let mut first = audit.submit(event(1)).await?;

        let waited = first.wait(Duration::from_secs(1)).await;

        assert!(matches!(waited, Err(AuditError::Pending)), "{waited:?}");
        assert!(first.is_pending(), "the entry stays queued");
        assert!(audit.is_alive(), "a lock timeout is not a writer failure");
        drop(held);
        let second = audit.append(event(2)).await?;
        let written = first.wait(Duration::from_secs(1)).await?;
        assert_eq!(
            (written.seq, second.seq),
            (1, 2),
            "written in submission order"
        );
        Ok(())
    }
}
