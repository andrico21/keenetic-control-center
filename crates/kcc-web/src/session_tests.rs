//! Unit tests of which sessions the accounts still back.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    iter,
    net::{IpAddr, Ipv6Addr},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use kcc_app::{
    accounts::{AccountChange, AccountStore, Clock, NewAccount, SystemClock},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
};
use kcc_i18n::locale::Locale;
use secrecy::SecretString;
use tempfile::TempDir;

use super::{SessionId, SessionStore, account::SignedIn};

/// A Unix clock the test moves by hand.
#[derive(Debug, Default)]
struct MockClock(AtomicU64);

impl Clock for MockClock {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A store with an hour of idle time and two of lifetime for signed-in sessions.
fn store(clock: Arc<dyn Clock>) -> SessionStore {
    SessionStore::new(
        Duration::from_hours(1),
        Duration::from_hours(2),
        Locale::En,
        clock,
    )
}

/// The documentation address `2001:db8::<n>` of the `n`th test client.
fn client(n: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n))
}

/// The number of sessions before login held by the store.
async fn anonymous(store: &SessionStore) -> usize {
    store
        .inner
        .sessions
        .read()
        .await
        .values()
        .filter(|session| !session.is_authenticated())
        .count()
}

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
    let (anonymous, _session) = store.create_anonymous(None).await?;
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

/// SEC1-07, W1-03: the login page of one client address holds at most 64 sessions
/// before login; the 65th evicts that address's oldest, and other addresses keep theirs.
#[tokio::test]
async fn one_client_holds_at_most_64_anonymous_sessions() -> Result<(), Box<dyn Error>> {
    let store = store(Arc::new(MockClock::default()));
    let other = store.create_anonymous(Some(client(2))).await?.0;
    let mut ids: Vec<SessionId> = Vec::new();
    for _ in 0_u8..65 {
        ids.push(store.create_anonymous(Some(client(1))).await?.0);
    }

    let mut live = Vec::new();
    for id in &ids {
        live.push(store.peek(id).await.is_some());
    }
    assert_eq!(
        live.iter().filter(|kept| **kept).count(),
        64,
        "per-client cap"
    );
    assert_eq!(live.first(), Some(&false), "the oldest is evicted");
    assert!(
        store.peek(&other).await.is_some(),
        "another client lost its session"
    );
    Ok(())
}

/// SEC1-07, W1-03: a flood of login-page sessions from many addresses stays at 10 000
/// sessions before login; the next one evicts the oldest, and signed-in sessions stay.
#[tokio::test]
async fn anonymous_sessions_stay_at_10_000() -> Result<(), Box<dyn Error>> {
    let store = store(Arc::new(MockClock::default()));
    let viewer = Role::new(
        "viewer".to_owned(),
        [Permission::Read],
        vec!["*".to_owned()],
    );
    let account = SignedIn::new("kept".to_owned(), viewer, None);
    let signed_in = store.login(None, account, Locale::En).await?.0;
    let mut first = None;
    let flood = (0..157_u16).flat_map(|n| iter::repeat_n(client(n), 64));
    for address in flood.take(10_000) {
        let id = store.create_anonymous(Some(address)).await?.0;
        let _: &mut SessionId = first.get_or_insert(id);
    }
    assert_eq!(anonymous(&store).await, 10_000, "filled to the cap");

    let newest = store.create_anonymous(Some(client(9_999))).await?.0;

    assert_eq!(anonymous(&store).await, 10_000, "global cap");
    let oldest = first.ok_or("no session")?;
    assert!(store.peek(&oldest).await.is_none(), "the oldest is evicted");
    assert!(store.peek(&newest).await.is_some(), "the newest is kept");
    assert!(
        store.peek(&signed_in).await.is_some(),
        "a signed-in session was evicted"
    );
    Ok(())
}

/// SEC1-07: a session before login ends after 5 minutes without use, while a signed-in
/// session keeps the configured idle timeout.
#[tokio::test]
async fn anonymous_sessions_end_after_five_idle_minutes() -> Result<(), Box<dyn Error>> {
    let clock = Arc::new(MockClock::default());
    let store = store(Arc::<MockClock>::clone(&clock));
    let viewer = Role::new(
        "viewer".to_owned(),
        [Permission::Read],
        vec!["*".to_owned()],
    );
    let account = SignedIn::new("kept".to_owned(), viewer, None);
    let signed_in = store.login(None, account, Locale::En).await?.0;
    let fresh = store.create_anonymous(Some(client(1))).await?.0;

    let _: u64 = clock.0.fetch_add(299, Ordering::SeqCst);
    assert!(store.peek(&fresh).await.is_some(), "ended before 5 minutes");
    let _: u64 = clock.0.fetch_add(1, Ordering::SeqCst);

    assert!(
        store.peek(&fresh).await.is_none(),
        "alive after 5 idle minutes"
    );
    assert!(
        store.peek(&signed_in).await.is_some(),
        "the signed-in session ended"
    );
    Ok(())
}
