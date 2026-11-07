//! Administrative account-password reset policy tests.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests assert account storage and authentication behavior"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};

use kcc_app::{
    accounts::{
        AccountError, AccountStore, Authentication, Clock, MAX_PASSWORD_CHARS, NewAccount,
        SystemClock,
    },
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
};
use secrecy::SecretString;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

fn fixture() -> Result<(TempDir, AccountStore), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    let accounts = AccountStore::new(
        state,
        MasterKey::generate()?,
        Duration::from_secs(60),
        clock,
    );
    accounts.create(NewAccount::new(
        "admin".to_owned(),
        SecretString::from("original admin passphrase"),
        "admin".to_owned(),
    ))?;
    accounts.create(NewAccount::new(
        "alice".to_owned(),
        SecretString::from("original viewer passphrase"),
        "viewer".to_owned(),
    ))?;
    Ok((temp, accounts))
}

fn role(name: &str, permissions: &[Permission]) -> Role {
    Role::new(
        name.to_owned(),
        permissions.iter().copied(),
        vec!["*".to_owned()],
    )
}

#[test]
fn admin_reset_authenticates_with_new_password_and_forces_change() -> TestResult {
    let (_temp, accounts) = fixture()?;
    let admin = role("admin", &Permission::ALL);
    let changed = accounts.reset_password(
        ("admin", &admin),
        "alice",
        &SecretString::from("new viewer passphrase"),
    )?;

    assert!(changed, "target account exists");
    assert_eq!(
        accounts.authenticate("alice", &SecretString::from("original viewer passphrase"))?,
        Authentication::Invalid,
        "old password is invalidated"
    );
    assert!(
        matches!(
            accounts.authenticate("alice", &SecretString::from("new viewer passphrase"))?,
            Authentication::Authenticated { role, locale } if role == "viewer" && locale == "en"
        ),
        "new password authenticates"
    );
    assert!(
        accounts
            .list()?
            .into_iter()
            .any(|account| account.username == "alice" && account.must_change_password),
        "administrative reset forces a subsequent password change"
    );
    Ok(())
}

#[test]
fn role_without_manage_users_is_refused_without_state_change() -> TestResult {
    let (_temp, accounts) = fixture()?;
    let viewer = role("viewer", &[Permission::Read]);

    let reset = accounts.reset_password(
        ("alice", &viewer),
        "admin",
        &SecretString::from("replacement admin passphrase"),
    );

    assert!(
        matches!(reset, Err(AccountError::PermissionDenied)),
        "permission gate"
    );
    assert!(
        matches!(
            accounts.authenticate("admin", &SecretString::from("original admin passphrase"))?,
            Authentication::Authenticated { role, locale: _ } if role == "admin"
        ),
        "original state is preserved"
    );
    assert_eq!(
        accounts.authenticate("admin", &SecretString::from("replacement admin passphrase"))?,
        Authentication::Invalid,
        "refused replacement was not stored"
    );
    Ok(())
}

#[test]
fn self_reset_and_non_admin_reset_of_admin_are_refused() -> TestResult {
    let (_temp, accounts) = fixture()?;
    let admin = role("admin", &Permission::ALL);
    let manager = role("manager", &[Permission::ManageUsers]);

    let own = accounts.reset_password(
        ("admin", &admin),
        "admin",
        &SecretString::from("replacement admin passphrase"),
    );
    let target_admin = accounts.reset_password(
        ("alice", &manager),
        "admin",
        &SecretString::from("replacement admin passphrase"),
    );

    assert!(
        matches!(own, Err(AccountError::SelfResetRequiresCurrentPassword)),
        "self reset retains the current-password path"
    );
    assert!(
        matches!(target_admin, Err(AccountError::AdminResetRequiresAdmin)),
        "only another persisted enabled admin may reset an admin"
    );
    Ok(())
}

#[test]
fn reset_refuses_control_characters_and_passwords_over_the_limit() -> TestResult {
    let (_temp, accounts) = fixture()?;
    let admin = role("admin", &Permission::ALL);
    let control = accounts.reset_password(
        ("admin", &admin),
        "alice",
        &SecretString::from("valid length\npassword"),
    );
    let too_long = accounts.reset_password(
        ("admin", &admin),
        "alice",
        &SecretString::from("x".repeat(MAX_PASSWORD_CHARS.saturating_add(1))),
    );

    assert!(
        matches!(control, Err(AccountError::InvalidPasswordCharacters)),
        "control characters are refused"
    );
    assert!(
        matches!(too_long, Err(AccountError::InvalidPasswordLength)),
        "oversized passwords are refused"
    );
    Ok(())
}
