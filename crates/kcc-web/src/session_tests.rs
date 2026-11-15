//! Unit tests of which sessions the accounts still back.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};

use kcc_app::{
    accounts::{AccountChange, AccountStore, Clock, NewAccount, SystemClock},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
};
use kcc_i18n::locale::Locale;
use secrecy::SecretString;
use tempfile::TempDir;

use super::{SessionStore, account::SignedIn};

/// A deleted account, one with another role, and a session that signed in without a
/// readable password fingerprint end; a backed session and one before login stay.
#[tokio::test]
async fn sessions_end_when_their_account_no_longer_backs_them() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    let accounts = Arc::new(AccountStore::new(
        StateStore::open(&temp.path().join("state"))?,
        MasterKey::from_bytes([3_u8; 32]),
        Duration::from_mins(1),
        Arc::clone(&clock),
    ));
    let names = ["kept", "deleted", "promoted", "unread"];
    for name in names {
        let password = SecretString::from(["session", name, "passphrase"].join("-"));
        accounts.create(NewAccount::new(
            name.to_owned(),
            password,
            "viewer".to_owned(),
        ))?;
    }
    let store = SessionStore::new(
        Duration::from_hours(1),
        Duration::from_hours(2),
        Locale::En,
        clock,
    );
    let viewer = Role::new(
        "viewer".to_owned(),
        [Permission::Read],
        vec!["*".to_owned()],
    );
    let mut ids = Vec::new();
    for name in names {
        let fingerprint = if name == "unread" {
            None
        } else {
            accounts.fingerprint(name)?
        };
        let account = SignedIn::new(name.to_owned(), viewer.clone(), fingerprint);
        ids.push(store.login(None, account, Locale::En).await?.0);
    }
    let (anonymous, _session) = store.create_anonymous().await?;
    let _deleted = accounts.administer("deleted", &AccountChange::Delete)?;
    let _promoted = accounts.administer("promoted", &AccountChange::Role("operator".to_owned()))?;

    let reader = Arc::clone(&accounts);
    let (standings, ended) = store.end_stale(move || reader.standings()).await?;

    assert_eq!(standings.len(), 3, "the deleted account is gone");
    assert_eq!(ended, 3, "deleted, promoted and unread end");
    let mut live = Vec::new();
    for id in &ids {
        live.push(store.peek(id).await.is_some());
    }
    assert_eq!(
        live,
        [true, false, false, false],
        "only the backed session stays"
    );
    assert!(
        store.peek(&anonymous).await.is_some(),
        "a session before login stays"
    );
    Ok(())
}
