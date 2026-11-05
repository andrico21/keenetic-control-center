//! Serialized, tamper-evident audit logging with size-based rotation.

use core::fmt;
extern crate alloc;

use alloc::collections::BTreeMap;
use std::{
    fs::{self, File},
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::{Value, error::Category};
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, oneshot};

use crate::persist::{StateError, StateStore, io_error, open_private_append_file};

/// Default audit rotation threshold: 50 MiB.
pub const DEFAULT_ROTATE_BYTES: u64 = 50 * 1024 * 1024;
/// Active audit file name.
pub const AUDIT_FILE_NAME: &str = "audit.jsonl";
/// All-zero hash before the first audit entry.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

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
    /// Creates an audit principal.
    #[inline]
    #[must_use]
    pub const fn new(kind: ActorKind, id: String) -> Self {
        Self { kind, id }
    }
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
        /// Completion signal.
        reply: oneshot::Sender<Result<AuditEntry, AuditError>>,
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
        Self::spawn_with_limit(store, DEFAULT_ROTATE_BYTES)
    }

    /// Starts the writer with a custom rotation limit, primarily for bounded
    /// tests. Production callers use [`Self::spawn`].
    ///
    /// # Errors
    ///
    /// Returns an I/O, parse, or chain error while recovering the chain tail.
    #[inline]
    pub fn spawn_with_limit(store: &StateStore, rotate_bytes: u64) -> Result<Self, AuditError> {
        let _lock = store.lock(AUDIT_FILE_NAME)?;
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
            dir: store.dir().to_owned(),
            file,
            current_bytes: fs::metadata(&path).map_or(0, |metadata| metadata.len()),
            rotate_bytes,
            next_seq,
            previous_hash,
        };
        drop(tokio::spawn(writer_task(receiver, state)));
        Ok(Self { sender })
    }

    /// Appends one audit event after rejecting secret-shaped parameter keys.
    ///
    /// # Errors
    ///
    /// Returns a validation, serialization, I/O, or writer-lifecycle error.
    ///
    /// Cancel safety: not cancel-safe. Once sent, the single writer may append
    /// the event even if the caller stops awaiting the acknowledgement.
    #[inline]
    pub async fn append(&self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        reject_secret_parameters(&event.params_redacted)?;
        let (reply, result) = oneshot::channel();
        self.sender
            .send(Command::Append { event, reply })
            .await
            .map_err(|_error| AuditError::WriterUnavailable)?;
        result
            .await
            .map_err(|_error| AuditError::WriterUnavailable)?
    }
}

/// Mutable state owned exclusively by the writer task.
#[derive(Debug)]
struct WriterState {
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
}

/// Runs the sole append/rotation loop.
async fn writer_task(mut receiver: mpsc::Receiver<Command>, mut state: WriterState) {
    while let Some(command) = receiver.recv().await {
        match command {
            Command::Append { event, reply } => {
                let result = state.append(event);
                drop(reply.send(result));
            }
        }
    }
}

impl WriterState {
    /// Hashes, rotates if needed, appends, syncs, then advances chain state.
    ///
    /// # Errors
    ///
    /// Returns serialization, I/O, or rotation errors.
    fn append(&mut self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
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

/// Discovers rotated files in sequence order, followed by the active file.
///
/// # Errors
///
/// Returns an I/O error when the audit directory cannot be listed.
fn audit_files(dir: &Path) -> Result<Vec<PathBuf>, AuditError> {
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
    let active = dir.join(AUDIT_FILE_NAME);
    if active.exists() {
        rotated.push(active);
    }
    Ok(rotated)
}

/// Verifies a caller-ordered list of chain files.
///
/// # Errors
///
/// Returns the first I/O, JSON, or chain validation error.
fn verify_files(files: &[PathBuf]) -> Result<Vec<AuditEntry>, AuditError> {
    let mut entries = Vec::new();
    let mut expected_sequence = 1_u64;
    let mut previous_hash = GENESIS_HASH.to_owned();
    for path in files {
        let file = File::open(path).map_err(|error| io_error(path, error))?;
        for read_result in BufReader::new(file).lines() {
            let line = read_result.map_err(|error| io_error(path, error))?;
            if line.is_empty() {
                continue;
            }
            let entry: AuditEntry =
                serde_json::from_str(&line).map_err(|error| json_error(&error))?;
            if entry.seq != expected_sequence || entry.prev_hash != previous_hash {
                return Err(AuditError::Chain { seq: entry.seq });
            }
            let calculated = calculate_hash(&entry)?;
            if entry.hash != calculated {
                return Err(AuditError::Chain { seq: entry.seq });
            }
            expected_sequence = expected_sequence.saturating_add(1);
            previous_hash.clone_from(&entry.hash);
            entries.push(entry);
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
    let reason = match error.classify() {
        Category::Io => "I/O",
        Category::Syntax => "syntax",
        Category::Data => "data",
        Category::Eof => "end of input",
    };
    AuditError::Json {
        reason: reason.to_owned(),
    }
}
