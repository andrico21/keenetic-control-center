//! The single audit writer task.
//!
//! The log's order and its hash chain rest on these invariants:
//!
//! - **One writer, first in first out.** One task per process consumes the one command
//!   channel in order and takes the next entry only after the previous one is written,
//!   so an entry is never written before one submitted earlier in the same process. The
//!   channel is unbounded, so submitting never waits for the writer; the slot a bounded
//!   caller took for its entry is given back once the entry is written.
//! - **The chain is extended under the lock.** The sequence number and previous hash are
//!   read from the last line of the newest file while the cross-process append lock is
//!   held, right before the entry is hashed and appended, so the entries of every process
//!   sharing the state directory form one contiguous chain. Only that line is read; the
//!   whole chain is verified when a writer starts and by `kcc audit verify`.
//! - **A torn last line is moved aside, not refused.** A last line without its `\n` (a
//!   crash or a full disk mid-append) is moved to a quarantine file under the lock and the
//!   repair is recorded as an entry; a complete line that does not verify is fatal.
//! - **A busy lock keeps the entry at the head.** When another process holds the lock
//!   past one bounded round of attempts, the writer starts another round for the same
//!   entry; it never skips or drops it. Callers stopped waiting long before (their waits
//!   are bounded, see [`super::receipt`]), and their entries stay queued behind it.
//! - **Any other failure is fatal.** The writer answers that entry as failed, closes the
//!   channel and stops: the entries still queued are dropped and their handles report
//!   the writer as unavailable, the slots of bounded callers are closed, and
//!   [`super::AuditLog::is_alive`] turns false, so new changes are refused before any
//!   router request.
//! - **Subscribers only observe.** Each entry written (a repair entry right before the
//!   entry whose append made it) goes to the receivers of [`super::AuditLog::subscribe`]
//!   after it is synced; the send never waits, and its only failure, no receiver, is
//!   ignored.

extern crate alloc;

use alloc::sync::Arc;

use tokio::{
    sync::{mpsc, watch},
    task::spawn_blocking,
};

use super::{
    AuditError, Command, Progress, WriterState,
    append_lock::{RetryPolicy, acquire_append_lock},
    receipt::Reply,
};
use crate::persist::{StateLock, StateStore};

/// Runs the sole append and rotation loop, reporting its `progress`.
// cancel-safe: the task is spawned once and owned by the runtime; an entry it holds is
// written or answered as failed before the next one is taken.
pub(super) async fn writer_task(
    mut receiver: mpsc::UnboundedReceiver<Command>,
    mut state: WriterState,
    progress: Arc<Progress>,
) {
    while let Some(Command::Append {
        event,
        reply,
        holds_slot,
    }) = receiver.recv().await
    {
        let lock = match locked(state.store(), state.append_lock_retry()).await {
            Ok(lock) => lock,
            Err(error) => {
                stop(&error, (&reply, &mut receiver, &progress));
                break;
            }
        };
        let joined = spawn_blocking(move || {
            let result = state.append_locked(event, &lock);
            (state, result)
        })
        .await;
        let Ok((returned, result)) = joined else {
            stop(
                &AuditError::WriterUnavailable,
                (&reply, &mut receiver, &progress),
            );
            break;
        };
        state = returned;
        match result {
            Ok((repaired, entry)) => {
                // Subscribers only observe: a send fails only when nobody subscribed, and
                // a lagging receiver loses its oldest entries instead of holding the writer.
                if let Some(repair) = repaired {
                    drop(progress.written.send(repair));
                }
                drop(reply.send_replace(Reply::Written(entry.clone())));
                drop(progress.written.send(entry));
                progress
                    .queued
                    .send_modify(|count| *count = count.saturating_sub(1));
                if holds_slot {
                    progress.slots.add_permits(1);
                }
            }
            Err(error) => {
                stop(&error, (&reply, &mut receiver, &progress));
                break;
            }
        }
    }
}

/// Takes the append lock, starting another bounded round while another process holds it.
///
/// # Errors
///
/// Returns the state error of opening or locking the sidecar; never a busy lock.
// cancel-safe: every failed attempt owns no lock, and a successful lock is returned by value.
async fn locked(store: &StateStore, retry: RetryPolicy) -> Result<StateLock, AuditError> {
    loop {
        match acquire_append_lock(store, retry).await {
            Err(AuditError::AppendLockTimeout) => {
                tracing::warn!(
                    "audit append lock still held by another process; the entry stays queued"
                );
            }
            acquired @ (Ok(_)
            | Err(
                AuditError::State(_)
                | AuditError::Json { reason: _ }
                | AuditError::Chain { seq: _ }
                | AuditError::WriterUnavailable
                | AuditError::SecretParameter { key: _ }
                | AuditError::Pending
                | AuditError::QueueFull,
            )) => return acquired,
        }
    }
}

/// Ends the writer after a fatal `error`: closes the channel and the bounded callers'
/// slots, answers the entry as failed and wakes whoever waits for the queue to drain.
fn stop(
    error: &AuditError,
    (reply, receiver, progress): (
        &watch::Sender<Reply>,
        &mut mpsc::UnboundedReceiver<Command>,
        &Progress,
    ),
) {
    tracing::error!(%error, "audit writer failed; the entries still queued are lost");
    receiver.close();
    progress.slots.close();
    drop(reply.send_replace(Reply::Failed));
    progress.queued.send_modify(|_count| {});
}
