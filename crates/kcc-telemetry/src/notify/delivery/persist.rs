//! The outbox's writes to `notify_state.json`, off the async threads.

use alloc::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::{
    notify_store::{DisabledChat, DisabledReason, NotifyRuntime, recipients::ChatId},
    persist::{Edit, StateError, StateStore},
};
use tokio::task::spawn_blocking;

/// Now in Unix seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Runs `work` on the blocking pool and logs a failure; answers `None` then.
// cancel-safe: the blocking work finishes even when the caller is dropped, and each
// update is one atomic file replacement.
async fn blocking<T, F>(store: &StateStore, work: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce(&StateStore) -> Result<T, StateError> + Send + 'static,
{
    let owned = store.clone();
    match spawn_blocking(move || work(&owned)).await {
        Ok(Ok(value)) => Some(value),
        Ok(Err(error)) => {
            tracing::warn!(%error, "notification state update failed");
            None
        }
        Err(_join) => {
            tracing::warn!("notification state update did not finish");
            None
        }
    }
}

/// The delivery state; the defaults when it cannot be read.
// cancel-safe: only reads.
pub(super) async fn read(store: &StateStore) -> NotifyRuntime {
    blocking(store, StateStore::read::<NotifyRuntime>)
        .await
        .flatten()
        .unwrap_or_default()
}

/// Records that Telegram refused the bot token now.
// cancel-safe: see `blocking`.
pub(super) async fn token_rejected(store: &StateStore) {
    let now = unix_now();
    let _written: Option<()> = blocking(store, move |state| {
        state.update(|runtime: &mut NotifyRuntime| runtime.token_rejected_at = Some(now))
    })
    .await;
}

/// Records that Telegram refused `chat` now.
// cancel-safe: see `blocking`.
pub(super) async fn disable(store: &StateStore, chat: ChatId, reason: DisabledReason) {
    let now = unix_now();
    let _written: Option<()> = blocking(store, move |state| {
        state.update(|runtime: &mut NotifyRuntime| {
            let _previous: Option<DisabledChat> = runtime
                .disabled_chats
                .insert(chat, DisabledChat::new(reason, now));
        })
    })
    .await;
}

/// Forgets disabled marks of chats not in `listed` and, with `clear_rejection`, the
/// token refusal.
// cancel-safe: see `blocking`.
pub(super) async fn forget(store: &StateStore, listed: BTreeSet<ChatId>, clear_rejection: bool) {
    let _written: Option<()> = blocking(store, move |state| {
        state.update_if_changed(|runtime: &mut NotifyRuntime| {
            let before = runtime.disabled_chats.len();
            runtime
                .disabled_chats
                .retain(|chat, _| listed.contains(chat));
            let rejected = clear_rejection && runtime.token_rejected_at.take().is_some();
            if rejected || runtime.disabled_chats.len() != before {
                Edit::Changed(())
            } else {
                Edit::Unchanged(())
            }
        })
    })
    .await;
}
