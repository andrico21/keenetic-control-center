//! Argon2id password hashing and verification, one run per available CPU at a time.
//!
//! Each run takes [`ARGON2_MEMORY_KIB`](super::ARGON2_MEMORY_KIB) of memory, so a burst of
//! sign-ins would otherwise take that much per request. Callers run on blocking threads
//! and hold no state file lock while they wait here.

use core::num::NonZero;
use std::{
    sync::{Condvar, LazyLock, Mutex, PoisonError},
    thread,
};

use argon2::{
    Algorithm, Argon2, Version,
    password_hash::{PasswordHasher as _, PasswordVerifier as _, phc::PasswordHash},
};
use secrecy::{ExposeSecret as _, SecretString};

use super::{AccountError, password_params};

/// The Argon2 run slots of the process: one per CPU it may use.
static GATE: LazyLock<Gate> =
    LazyLock::new(|| Gate::new(thread::available_parallelism().map_or(1, NonZero::get)));

/// A counting semaphore for blocking threads.
#[derive(Debug)]
struct Gate {
    /// Run slots free now.
    free: Mutex<usize>,
    /// Signalled when a slot is given back.
    freed: Condvar,
}

/// A taken run slot, given back when dropped, whatever way the run ends.
#[derive(Debug)]
struct Permit {
    /// The gate the slot belongs to.
    gate: &'static Gate,
}

impl Gate {
    /// A gate with `slots` run slots.
    const fn new(slots: usize) -> Self {
        Self {
            free: Mutex::new(slots),
            freed: Condvar::new(),
        }
    }

    /// Takes a run slot, waiting while every slot is taken.
    fn enter(&'static self) -> Permit {
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        #[cfg(test)]
        {
            if *free == 0 {
                probe::emit(probe::Step::Waiting);
            }
        }
        loop {
            if let Some(left) = free.checked_sub(1) {
                *free = left;
                return Permit { gate: self };
            }
            free = self
                .freed
                .wait(free)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut free = self
            .gate
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *free = free.saturating_add(1);
        drop(free);
        self.gate.freed.notify_one();
    }
}

/// Hashes a password with Argon2id v19 and an OS-generated salt.
///
/// # Errors
///
/// Returns [`AccountError::PasswordHash`] if parameter setup, randomness, or
/// hashing fails.
pub(super) fn hash(password: &SecretString) -> Result<String, AccountError> {
    let params = password_params().map_err(|_error| AccountError::PasswordHash)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let _permit = GATE.enter();
    #[cfg(test)]
    probe::emit(probe::Step::Run(probe::Work::Hash));
    argon2
        .hash_password(password.expose_secret().as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|_error| AccountError::PasswordHash)
}

/// Verifies a supplied password against a stored PHC string.
///
/// # Errors
///
/// Returns [`AccountError::StoredPasswordHash`] if the persisted hash is not a
/// valid PHC string.
pub(super) fn verify(password: &SecretString, hash: &SecretString) -> Result<bool, AccountError> {
    let parsed = PasswordHash::new(hash.expose_secret())
        .map_err(|_error| AccountError::StoredPasswordHash)?;
    let _permit = GATE.enter();
    #[cfg(test)]
    probe::emit(probe::Step::Run(probe::Work::Verify));
    Ok(Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &parsed)
        .is_ok())
}

/// Performs the same Argon2id work as [`verify`] without a persisted hash.
///
/// It stands in for the check of a sign-in that has no password to check. The fixed salt
/// is public and exists only to equalize login work; no derived bytes leave this function.
///
/// # Errors
///
/// Returns [`AccountError::PasswordHash`] if the fixed Argon2 parameters or
/// hashing operation fail.
pub(super) fn verify_dummy(password: &SecretString) -> Result<(), AccountError> {
    let params = password_params().map_err(|_error| AccountError::PasswordHash)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0_u8; 32];
    let _permit = GATE.enter();
    #[cfg(test)]
    probe::emit(probe::Step::Run(probe::Work::Dummy));
    argon2
        .hash_password_into(
            password.expose_secret().as_bytes(),
            b"kcc-unknown-user",
            &mut output,
        )
        .map_err(|_error| AccountError::PasswordHash)
}

/// A per-thread observer of the Argon2 runs, so tests can count them and hold one up.
#[cfg(test)]
pub(super) mod probe {
    extern crate alloc;

    use alloc::rc::Rc;
    use core::cell::RefCell;

    /// What one Argon2 run is for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Work {
        /// Hashing a new password.
        Hash,
        /// Checking a password against a stored hash.
        Verify,
        /// The stand-in check of a sign-in with no password to check.
        Dummy,
    }

    /// A point an Argon2 run passes.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Step {
        /// Every run slot is taken; the thread waits for one.
        Waiting,
        /// The run is about to start.
        Run(Work),
    }

    /// Called at every step of one thread's Argon2 runs.
    pub(crate) type Observer = Rc<dyn Fn(Step)>;

    thread_local! {
        /// The observer of the current thread's runs.
        static PROBE: RefCell<Option<Observer>> = const { RefCell::new(None) };
    }

    /// Calls `observer` at every step of the current thread's Argon2 runs.
    pub(crate) fn install(observer: Observer) {
        PROBE.with_borrow_mut(|slot| *slot = Some(observer));
    }

    /// Reports `step` to the current thread's observer, if any.
    pub(super) fn emit(step: Step) {
        if let Some(observer) = PROBE.with_borrow(Clone::clone) {
            observer(step);
        }
    }
}
