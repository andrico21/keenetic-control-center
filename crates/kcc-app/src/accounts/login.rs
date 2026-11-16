//! Sign-in. The password is checked against a snapshot of `users.json` read without the
//! lock; the file is locked, and written, only when the account's failure count or
//! lockout changes.

use secrecy::SecretString;

use super::{
    Account, AccountError, AccountStore, Authentication, UsersDocument, hashing, validate_username,
};
use crate::{persist::Edit, secrets::binding::Binding};

/// How often a sign-in starts over because the password changed while it was checked;
/// past that it is refused without counting a failure.
const ATTEMPTS: usize = 3;

/// An account's failed-attempt count and lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counters {
    /// Consecutive failed attempts.
    failures: u32,
    /// Unix timestamp through which login is locked.
    lockout_until: Option<u64>,
}

impl Counters {
    /// No failures and no lockout.
    const CLEAR: Self = Self {
        failures: 0,
        lockout_until: None,
    };

    /// The counters of `account`.
    const fn of(account: &Account) -> Self {
        Self {
            failures: account.failure_count,
            lockout_until: account.lockout_until,
        }
    }
}

/// One checked attempt: whether the password matched, and when it was made.
#[derive(Debug, Clone, Copy)]
struct Check {
    /// Whether the password matched the hash of the snapshot.
    matched: bool,
    /// Unix time of the attempt.
    now: u64,
}

/// How recording a check ended.
#[derive(Debug)]
enum Settled {
    /// The sign-in's answer.
    Answer(Authentication),
    /// The password changed after the snapshot; the check proves nothing about it.
    Stale,
}

/// Authenticates `username` with no Argon2 check under the `users.json` lock.
///
/// Every outcome runs exactly one Argon2 check per snapshot (the stand-in one for
/// unknown, disabled and locked accounts), so its timing does not tell them apart.
///
/// # Errors
///
/// A state, decryption, hashing or stored-hash error.
pub(super) fn authenticate(
    store: &AccountStore,
    username: &str,
    password: &SecretString,
) -> Result<Authentication, AccountError> {
    let valid_name = validate_username(username).is_ok();
    for _attempt in 0..ATTEMPTS {
        let snapshot = store.state.read::<UsersDocument>()?.unwrap_or_default();
        let Some(account) = snapshot
            .users
            .into_iter()
            .find(|candidate| valid_name && candidate.username == username)
        else {
            hashing::verify_dummy(password)?;
            return Ok(Authentication::Invalid);
        };
        let now = store.clock.unix_seconds();
        if account.disabled {
            hashing::verify_dummy(password)?;
            return Ok(Authentication::Disabled);
        }
        if let Some(until) = locked_until(&account, now) {
            hashing::verify_dummy(password)?;
            return Ok(Authentication::Locked { until });
        }
        let hash = store
            .key
            .open(&Binding::account(&account.username), &account.password_hash)?;
        let matched = hashing::verify(password, &hash)?;
        match settle(store, &account, Check { matched, now })? {
            Settled::Answer(answer) => return Ok(answer),
            Settled::Stale => {}
        }
    }
    Ok(Authentication::Invalid)
}

/// Records `check`, made against the snapshot `seen`, with a compare-and-set.
///
/// Nothing is locked or written when the counters stay as they are. Otherwise, under
/// the lock, the account must still have the snapshot's sealed hash (else the check is
/// [`Settled::Stale`]) and must not have been disabled meanwhile; the counter step is
/// then applied to the counters as they stand, so simultaneous attempts each count once
/// and none passes a lockout another set.
///
/// # Errors
///
/// A state error.
fn settle(store: &AccountStore, seen: &Account, check: Check) -> Result<Settled, AccountError> {
    let (counters, answer) = step(store, seen, check);
    if counters == Counters::of(seen) {
        return Ok(Settled::Answer(answer));
    }
    let settled = store
        .state
        .update_if_changed(|document: &mut UsersDocument| {
            let Some(account) = document
                .users
                .iter_mut()
                .find(|candidate| candidate.username == seen.username)
            else {
                return Edit::Unchanged(Settled::Answer(Authentication::Invalid));
            };
            if account.password_hash != seen.password_hash {
                return Edit::Unchanged(Settled::Stale);
            }
            if account.disabled {
                return Edit::Unchanged(Settled::Answer(Authentication::Disabled));
            }
            let (fresh, reply) = step(store, account, check);
            if fresh == Counters::of(account) {
                return Edit::Unchanged(Settled::Answer(reply));
            }
            account.failure_count = fresh.failures;
            account.lockout_until = fresh.lockout_until;
            Edit::Changed(Settled::Answer(reply))
        })?;
    Ok(settled)
}

/// The counters `account` gets from `check`, and the sign-in's answer.
fn step(store: &AccountStore, account: &Account, check: Check) -> (Counters, Authentication) {
    if let Some(until) = locked_until(account, check.now) {
        return (Counters::of(account), Authentication::Locked { until });
    }
    if check.matched {
        let answer = Authentication::Authenticated {
            role: account.role.clone(),
            locale: account.locale.clone(),
        };
        return (Counters::CLEAR, answer);
    }
    let earlier = if account.lockout_until.is_some() {
        0
    } else {
        account.failure_count
    };
    let failures = earlier.saturating_add(1);
    if failures >= store.max_failures {
        let until = check.now.saturating_add(store.lockout.as_secs());
        let counters = Counters {
            failures,
            lockout_until: Some(until),
        };
        return (counters, Authentication::Locked { until });
    }
    let counters = Counters {
        failures,
        lockout_until: None,
    };
    (counters, Authentication::Invalid)
}

/// The end of `account`'s lockout, while it lasts at `now`.
fn locked_until(account: &Account, now: u64) -> Option<u64> {
    account.lockout_until.filter(|&until| now < until)
}
