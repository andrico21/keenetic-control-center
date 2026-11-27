//! Audit entries this process writes: failed changes, account lockouts, audit repairs,
//! the audit writer stopping, and the restarts kcc itself sends, which mute the router's
//! offline and online messages.
//!
//! Only this process's writer is followed: entries other processes (the CLI, `kcc mcp
//! stdio`) append to the shared log are not notified.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{audit::AuditEntry, notify_store::NotifyEvent};
use serde_json::Value;
use tokio::{sync::broadcast::error::RecvError, task::spawn_blocking};

use super::{Shared, memory::Lockouts, render};

/// How long a restart kcc sent mutes the router's offline and online messages, in seconds.
const MUTE_SECONDS: u64 = 15 * 60;

/// The `router.change_cli*` targets that restart the router or roll it back.
const RESTARTS: [&str; 3] = [
    "system reboot",
    "system configuration fail-safe rollback",
    "components commit",
];

/// A failed change, as its audit entry tells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ChangeFailure {
    /// The router, when the change had one.
    router: Option<String>,
    /// The stable action id.
    action: String,
    /// `kind:id` of the actor.
    actor: String,
    /// Whether the router's fail-safe timer is still armed.
    fail_safe_armed: bool,
}

impl ChangeFailure {
    /// The router, when the change had one.
    pub(super) fn router(&self) -> Option<&str> {
        self.router.as_deref()
    }

    /// The stable action id.
    pub(super) fn action(&self) -> &str {
        &self.action
    }

    /// `kind:id` of the actor.
    pub(super) fn actor(&self) -> &str {
        &self.actor
    }

    /// Whether the router's fail-safe timer is still armed.
    pub(super) const fn fail_safe_armed(&self) -> bool {
        self.fail_safe_armed
    }
}

/// What an audit entry is worth a message for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Signal {
    /// A change failed (scheduled runs report their own).
    ChangeFailed(ChangeFailure),
    /// A Web sign-in found the account locked.
    AccountLocked(String),
    /// The audit log was repaired; the torn entry went to this file.
    Repaired(String),
}

/// What one audit entry means to the notifier.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Classified {
    /// The message it is worth.
    signal: Option<Signal>,
    /// A router whose offline and online messages are muted until a Unix time.
    mute: Option<(String, u64)>,
}

/// Classifies `entry`.
pub(super) fn classify(entry: &AuditEntry) -> Classified {
    let restart = entry
        .target
        .as_deref()
        .is_some_and(|target| RESTARTS.iter().any(|line| target.contains(line)));
    let mute = (restart
        && matches!(
            entry.action.as_str(),
            "router.change_cli" | "router.change_cli_terminal"
        ))
    .then(|| {
        entry
            .router
            .clone()
            .map(|router| (router, entry.ts.saturating_add(MUTE_SECONDS)))
    })
    .flatten();
    let signal = match (entry.action.as_str(), entry.outcome.as_str()) {
        ("audit.repair", _) => Some(Signal::Repaired(
            entry
                .params_redacted
                .get("file")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        )),
        ("web.login", "locked") => Some(Signal::AccountLocked(entry.actor.id.clone())),
        (_, "failed") if !entry.actor.id.starts_with("schedule:") => {
            Some(Signal::ChangeFailed(ChangeFailure {
                router: entry.router.clone(),
                action: entry.action.clone(),
                actor: actor(entry),
                fail_safe_armed: entry.params_redacted.get("fail_safe_armed")
                    == Some(&Value::Bool(true)),
            }))
        }
        _ => None,
    };
    Classified { signal, mute }
}

/// `kind:id` of the entry's actor.
fn actor(entry: &AuditEntry) -> String {
    let kind = serde_json::to_value(entry.actor.kind)
        .ok()
        .and_then(|kind| kind.as_str().map(str::to_owned))
        .unwrap_or_default();
    format!("{kind}:{}", entry.actor.id)
}

/// Follows this process's audit writer until it stops: the repair found at its start,
/// then every entry; a dead writer is reported once.
// cancel-safe: each entry is handled whole or not at all, and a dropped receiver misses
// only what was not handled.
pub(super) async fn follow(shared: Arc<Shared>) {
    let audit = shared.deps.audit.clone();
    let mut entries = audit.subscribe();
    let mut lockouts = Lockouts::default();
    if let Some(repair) = audit.startup_repair() {
        handle(&shared, &mut lockouts, &repair).await;
    }
    loop {
        tokio::select! {
            biased;
            received = entries.recv() => match received {
                Ok(entry) => handle(&shared, &mut lockouts, &entry).await,
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "notifier fell behind the audit log; entries skipped");
                }
                Err(RecvError::Closed) => return,
            },
            () = audit.closed() => {
                shared.writer_stopped();
                return;
            }
        }
    }
}

/// Acts on one entry.
// cancel-safe: a lockout lookup dropped midway sends nothing.
async fn handle(shared: &Shared, lockouts: &mut Lockouts, entry: &AuditEntry) {
    let Classified { signal, mute } = classify(entry);
    if let Some((router, until)) = mute {
        shared.mute(&router, until);
    }
    match signal {
        None => {}
        Some(Signal::ChangeFailed(failure)) => {
            let named = failure.router().map(|router| shared.router_name(router));
            shared.emit(NotifyEvent::ChangeFailed, |locale| {
                render::change_failed(locale, &failure, named.as_deref())
            });
        }
        Some(Signal::Repaired(file)) => shared.emit(NotifyEvent::AuditProblem, |locale| {
            render::audit_repaired(locale, &file)
        }),
        Some(Signal::AccountLocked(user)) => locked(shared, lockouts, user).await,
    }
}

/// Reports `user`'s lockout once per window, read from the accounts.
// cancel-safe: reads only; a dropped read sends nothing.
async fn locked(shared: &Shared, lockouts: &mut Lockouts, user: String) {
    if !shared.wants(NotifyEvent::AccountLocked) {
        return;
    }
    let accounts = Arc::clone(&shared.deps.accounts);
    let window = match spawn_blocking(move || accounts.list()).await {
        Ok(Ok(listed)) => listed
            .into_iter()
            .find(|account| account.username == user)
            .and_then(|account| account.lockout_until),
        Ok(Err(error)) => {
            tracing::warn!(%error, "accounts cannot be read for a lockout notification");
            return;
        }
        Err(error) => {
            tracing::warn!(%error, "accounts read for a lockout notification did not finish");
            return;
        }
    };
    let Some(until) = window else {
        return;
    };
    if lockouts.first(&user, until) {
        let shown = shared.local_time(until);
        shared.emit(NotifyEvent::AccountLocked, |locale| {
            render::account_locked(locale, &user, &shown)
        });
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests;
