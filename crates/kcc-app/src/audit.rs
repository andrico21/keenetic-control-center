//! Serialized, tamper-evident audit logging with size-based rotation.

use core::fmt;
extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    sync::{Semaphore, mpsc, watch},
    time::timeout,
};

use crate::{
    accounts::{Clock, SystemClock},
    persist::{StateError, StateStore, json_reason},
};

mod append_lock;
mod chain;
pub mod receipt;
mod repair;
pub mod request_id;
mod state;
mod tail;
mod writer;

use append_lock::RetryPolicy;
use chain::Check;
use receipt::{AUDIT_WAIT, Pending, Reply};
use state::WriterState;

/// Default audit rotation threshold: 50 MiB.
pub const DEFAULT_ROTATE_BYTES: u64 = 50 * 1024 * 1024;
/// Active audit file name.
pub const AUDIT_FILE_NAME: &str = "audit.jsonl";
/// Default audit retention: 365 days.
pub const DEFAULT_RETENTION: Duration = Duration::from_hours(365 * 24);
/// Queue slots shared by the callers of [`AuditLog::submit_within`].
const BOUNDED_SLOTS: usize = 128;
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
    /// No queue slot freed within the caller's limit: the entry was not queued and is
    /// never written.
    #[error("audit queue is full; the entry was not queued")]
    QueueFull,
}

/// A cloneable handle to the one audit writer task.
///
/// Every entry goes through one unbounded queue to the writer, so the log's order is the
/// order of submission. [`AuditLog::submit`] never waits and never drops an entry. The
/// accepted cost: while another process holds the append lock, entries keep arriving
/// (failing MCP calls, Web actions, change receipts) and the queue grows in memory until
/// the lock is free. Callers that must not act without their entry use
/// [`AuditLog::submit_within`] instead, which waits a bounded time for one of 128 slots.
#[derive(Clone)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public name is clearer than Log at call sites"
)]
pub struct AuditLog {
    /// Command channel consumed by exactly one task; unbounded, see the type's docs.
    sender: mpsc::UnboundedSender<Command>,
    /// The writer's progress.
    progress: Arc<Progress>,
}

/// What the handles and the writer share besides the channel.
#[derive(Debug)]
struct Progress {
    /// Entries submitted and not yet written.
    queued: watch::Sender<usize>,
    /// Free slots of [`AuditLog::submit_within`]. A slot is taken out of the semaphore
    /// for good when its entry is queued, and the writer adds it back once the entry is
    /// written; the writer closes the semaphore when it stops.
    slots: Semaphore,
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
        /// Whether the entry holds a slot of [`AuditLog::submit_within`].
        holds_slot: bool,
    },
}

impl AuditLog {
    /// Starts the single writer task for a state directory.
    ///
    /// # Errors
    ///
    /// Returns an I/O, parse, or chain error of the full verification at start.
    #[inline]
    pub fn spawn(store: &StateStore) -> Result<Self, AuditError> {
        Self::spawn_with_policy(store, AuditPolicy::default())
    }

    /// Starts the writer with an explicit rotation and retention policy.
    ///
    /// Verifies the whole chain first. When the append lock is free, it then moves a
    /// torn last line aside and records the repair; otherwise the writer does that
    /// before its first append.
    ///
    /// # Errors
    ///
    /// Returns an I/O, parse, or chain error of the verification or the repair.
    #[inline]
    pub fn spawn_with_policy(store: &StateStore, policy: AuditPolicy) -> Result<Self, AuditError> {
        let state = WriterState::new(store.clone(), policy);
        match store.try_lock(AUDIT_FILE_NAME) {
            Ok(lock) => {
                drop(verify_chain(store.dir())?);
                state.repair(&lock)?;
            }
            Err(StateError::StateLocked { path: _ }) => drop(verify_chain(store.dir())?),
            Err(error) => return Err(error.into()),
        }
        let (sender, receiver) = mpsc::unbounded_channel();
        let progress = Arc::new(Progress {
            queued: watch::Sender::new(0),
            slots: Semaphore::new(BOUNDED_SLOTS),
        });
        drop(tokio::spawn(writer::writer_task(
            receiver,
            state,
            Arc::clone(&progress),
        )));
        Ok(Self { sender, progress })
    }

    /// Queues one audit event after rejecting secret-shaped parameter keys, and returns
    /// the handle of the queued entry. It never waits: the entry is queued at once, behind
    /// every entry submitted before it.
    ///
    /// # Errors
    ///
    /// Returns a validation error, or [`AuditError::WriterUnavailable`] after a fatal
    /// writer failure.
    #[inline]
    pub fn submit(&self, event: AuditEvent) -> Result<Pending, AuditError> {
        reject_secret_parameters(&event.params_redacted)?;
        self.enqueue(event, false)
    }

    /// Queues one audit event like [`Self::submit`] once one of 128 slots is free.
    ///
    /// For a caller that must not act without its entry: it waits at most `limit` for the
    /// slot, which stays taken until the writer has written the entry.
    ///
    /// # Errors
    ///
    /// Returns a validation error, [`AuditError::QueueFull`] when no slot freed within
    /// `limit` (the entry is not queued and never written), or
    /// [`AuditError::WriterUnavailable`] after a fatal writer failure.
    // cancel-safe: cancelled while waiting for a slot, no slot is taken and nothing is
    // queued; once the slot is taken the entry is queued without another await.
    #[inline]
    pub async fn submit_within(
        &self,
        event: AuditEvent,
        limit: Duration,
    ) -> Result<Pending, AuditError> {
        reject_secret_parameters(&event.params_redacted)?;
        match timeout(limit, self.progress.slots.acquire()).await {
            Ok(Ok(slot)) => slot.forget(),
            Ok(Err(_closed)) => return Err(AuditError::WriterUnavailable),
            Err(_elapsed) => return Err(AuditError::QueueFull),
        }
        self.enqueue(event, true)
    }

    /// Hands a validated `event` to the writer, with the slot it took when `holds_slot`.
    ///
    /// # Errors
    ///
    /// [`AuditError::WriterUnavailable`] after a fatal writer failure.
    fn enqueue(&self, event: AuditEvent, holds_slot: bool) -> Result<Pending, AuditError> {
        let (reply, answer) = watch::channel(Reply::Queued);
        self.progress
            .queued
            .send_modify(|count| *count = count.saturating_add(1));
        let command = Command::Append {
            event,
            reply,
            holds_slot,
        };
        if self.sender.send(command).is_err() {
            self.progress
                .queued
                .send_modify(|count| *count = count.saturating_sub(1));
            if holds_slot {
                self.progress.slots.add_permits(1);
            }
            return Err(AuditError::WriterUnavailable);
        }
        Ok(Pending::new(answer))
    }

    /// Waits at most `limit` for every queued entry to be written, and returns how many
    /// were still queued then, or lost with a writer that failed.
    // cancel-safe: waiting only observes the writer's progress.
    #[inline]
    pub async fn flush(&self, limit: Duration) -> usize {
        let mut written = self.progress.queued.subscribe();
        let sender = &self.sender;
        let drained = written.wait_for(|count| *count == 0 || sender.is_closed());
        drop(timeout(limit, drained).await);
        *self.progress.queued.borrow()
    }

    /// Appends one audit event after rejecting secret-shaped parameter keys, waiting at
    /// most [`AUDIT_WAIT`] for it to be written. Queuing never waits ([`Self::submit`]).
    ///
    /// # Errors
    ///
    /// Returns a validation error, [`AuditError::Pending`] when the entry is still
    /// queued at the deadline (it is written later), or
    /// [`AuditError::WriterUnavailable`] after a fatal writer failure.
    #[inline]
    // NOT cancel-safe: the event is queued on the first poll, and the writer appends it
    // even if the caller stops awaiting.
    pub async fn append(&self, event: AuditEvent) -> Result<AuditEntry, AuditError> {
        self.submit(event)?.wait(AUDIT_WAIT).await
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

/// Verifies every rotated file and the active file as one continuous chain.
///
/// An unterminated last line of the active file is not an entry and is skipped: a crash
/// or another process's append in progress left it, and the next writer moves it aside.
///
/// # Errors
///
/// Returns the first invalid sequence in [`AuditError::Chain`], or an I/O/JSON
/// error if a line cannot be read or decoded.
#[inline]
pub fn verify_chain(dir: &Path) -> Result<Vec<AuditEntry>, AuditError> {
    chain::entries(dir, Check::Chain)
}

/// Reads every entry of the rotated files and the active file, in chain order, without
/// verifying the chain; for showing a log whose chain [`verify_chain`] rejects.
///
/// # Errors
///
/// Returns an I/O or JSON error if a file or line cannot be read or decoded.
#[inline]
pub fn read_entries(dir: &Path) -> Result<Vec<AuditEntry>, AuditError> {
    chain::entries(dir, Check::Parse)
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
    AuditError::Json {
        reason: json_reason(error),
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
        GENESIS_HASH, RetryPolicy, chain::calculate_hash, verify_chain,
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
        Ok(verify_chain(temp.path())?)
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
        let mut first = audit.submit(event(1))?;

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
