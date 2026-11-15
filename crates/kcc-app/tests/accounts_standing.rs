//! Account standings: the role, disabled flag and password fingerprint a signed-in Web
//! session is checked against.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests assert account storage behavior"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};

use kcc_app::{
    accounts::{AccountChange, AccountStore, Clock, NewAccount, SystemClock},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
};
use secrecy::SecretString;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

/// A password built at run time.
fn password(label: &str) -> SecretString {
    SecretString::from(["standing", label, "passphrase"].join("-"))
}

/// The account store over `state` with `key`.
fn store(state: &StateStore, key: MasterKey) -> AccountStore {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    AccountStore::new(state.clone(), key, Duration::from_secs(60), clock)
}

/// A state with `admin` and the viewer `alice`.
fn fixture() -> Result<(TempDir, StateStore, AccountStore), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let accounts = store(&state, MasterKey::from_bytes([9_u8; 32]));
    for (name, role) in [("admin", "admin"), ("alice", "viewer")] {
        accounts.create(NewAccount::new(
            name.to_owned(),
            password(name),
            role.to_owned(),
        ))?;
    }
    Ok((temp, state, accounts))
}

#[test]
fn the_fingerprint_changes_with_the_password_only() -> TestResult {
    let (_temp, _state, accounts) = fixture()?;
    let original = accounts
        .fingerprint("alice")?
        .ok_or("alice has a fingerprint")?;

    let _refused = accounts.authenticate("alice", &password("wrong"))?;
    let _found = accounts.set_locale("alice", "de".to_owned())?;
    let _before = accounts.administer("alice", &AccountChange::Unlock)?;
    let unchanged = accounts.standings()?;
    let standing = unchanged.get("alice").ok_or("alice is listed")?;
    assert_eq!(standing.fingerprint, Some(original), "no password change");
    assert_eq!(
        (standing.role.as_str(), standing.disabled),
        ("viewer", false)
    );

    let (_authentication, accepted) =
        accounts.change_password_for_session("alice", &password("alice"), &password("new"))?;
    let changed = accepted.ok_or("the change was accepted")?;
    assert_ne!(changed, original, "a new password has a new fingerprint");
    assert_eq!(
        accounts
            .standings()?
            .get("alice")
            .and_then(|alice| alice.fingerprint),
        Some(changed),
        "the session's fingerprint is the stored one"
    );

    let admin = Role::new(
        "admin".to_owned(),
        [Permission::ManageUsers],
        vec!["*".to_owned()],
    );
    assert!(accounts.reset_password(("admin", &admin), "alice", &password("reset"))?);
    assert_ne!(
        accounts.fingerprint("alice")?,
        Some(changed),
        "a reset changes it"
    );
    Ok(())
}

#[test]
fn a_hash_that_cannot_be_opened_has_no_fingerprint() -> TestResult {
    let (_temp, state, _accounts) = fixture()?;
    let foreign = store(&state, MasterKey::from_bytes([10_u8; 32]));

    let standings = foreign.standings()?;

    assert_eq!(standings.len(), 2, "every account is listed");
    assert!(
        standings
            .values()
            .all(|standing| standing.fingerprint.is_none()),
        "no session can match an account whose hash cannot be checked"
    );
    assert_eq!(foreign.fingerprint("alice")?, None);
    Ok(())
}
