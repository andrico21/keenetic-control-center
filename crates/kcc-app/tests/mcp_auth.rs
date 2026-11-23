//! The kcc OAuth authorization-server core: the Ed25519 signing key and access tokens,
//! the client registry, pending authorization requests and codes, refresh grants and the
//! per-call grant check.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use fallible filesystem fixtures and assertions"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kcc_app::{
    accounts::{AccountStore, Clock, NewAccount, standing::PasswordFingerprint},
    mcp_auth::{
        clients::{Client, ClientRegistration, ClientStore},
        grants::{GrantStore, IssuedGrant},
        pending::{AuthorizationRequest, CodeTarget, PendingStore, PkceChallenge},
    },
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
};
use ring::rand::{SecureRandom as _, SystemRandom};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

#[path = "mcp_auth/clients.rs"]
mod clients;
#[path = "mcp_auth/codes.rs"]
mod codes;
#[path = "mcp_auth/grants.rs"]
mod grants;
#[path = "mcp_auth/hygiene.rs"]
mod hygiene;
#[path = "mcp_auth/limits.rs"]
mod limits;
#[path = "mcp_auth/redirects.rs"]
mod redirects;
#[path = "mcp_auth/signing.rs"]
mod signing;

type TestResult = Result<(), Box<dyn Error>>;

/// The first instant of every fixture, in Unix seconds.
const START: u64 = 1_800_000_000;
/// The refresh token lifetime of every fixture (7 days).
const REFRESH_TTL: Duration = Duration::from_hours(7 * 24);
/// The resource every fixture grant is for.
const RESOURCE: &str = "https://kcc.example/mcp";

/// A clock the test moves by hand.
#[derive(Debug)]
struct ManualClock(AtomicU64);

impl ManualClock {
    /// Moves the clock `seconds` forward.
    fn advance(&self, seconds: u64) {
        let _previous: u64 = self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A state directory, a master key, a manual clock and every store over them.
struct Fixture {
    /// Keeps the state directory alive.
    _temp: TempDir,
    /// The state root.
    state: StateStore,
    /// The master key.
    key: MasterKey,
    /// The clock every store reads.
    clock: Arc<ManualClock>,
    /// Client registry.
    clients: ClientStore,
    /// Pending requests and codes.
    pending: PendingStore,
    /// Refresh grants.
    grants: GrantStore,
    /// Web accounts `alice` and `bob`.
    accounts: AccountStore,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let clock = Arc::new(ManualClock(AtomicU64::new(START)));
        let shared: Arc<dyn Clock> = Arc::<ManualClock>::clone(&clock);
        let accounts = AccountStore::new(
            state.clone(),
            MasterKey::from_bytes([7_u8; 32]),
            Duration::from_mins(1),
            Arc::clone(&shared),
        );
        let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        for name in ["alice", "bob"] {
            accounts.create(
                &admin,
                NewAccount::new(name.to_owned(), password(name), "viewer".to_owned()),
            )?;
        }
        Ok(Self {
            clients: ClientStore::new(state.clone(), Arc::clone(&shared)),
            pending: PendingStore::new(Arc::clone(&shared)),
            grants: GrantStore::new(state.clone(), Arc::clone(&shared), REFRESH_TTL),
            accounts,
            key: MasterKey::generate()?,
            state,
            clock,
            _temp: temp,
        })
    }

    /// Registers a dynamic client redirecting to `redirect`.
    fn client(&self, redirect: &str) -> Result<Client, Box<dyn Error>> {
        let registration =
            ClientRegistration::new(Some("Test client".to_owned()), vec![redirect.to_owned()]);
        Ok(self.clients.register(&registration)?)
    }

    /// The fingerprint of `account`'s current password.
    fn fingerprint(&self, account: &str) -> Result<PasswordFingerprint, Box<dyn Error>> {
        Ok(self
            .accounts
            .fingerprint(account)?
            .ok_or("account has a fingerprint")?)
    }

    /// Runs the code flow for `account` on `client` and returns the issued grant.
    fn connect(&self, client: &Client, account: &str) -> Result<IssuedGrant, Box<dyn Error>> {
        let verifier = verifier()?;
        let redirect = client.redirect_uris().first().ok_or("a redirect URI")?;
        let target = CodeTarget::new(client.id(), redirect, RESOURCE);
        let request = AuthorizationRequest::new(client, target.clone(), challenge(&verifier)?)?;
        let code = self.pending.issue_code(request, account)?;
        let authorized = self.pending.redeem(&code, &target, &verifier)?;
        Ok(self
            .grants
            .issue(&authorized, &self.fingerprint(account)?)?)
    }
}

/// A Web account password built at run time.
fn password(label: &str) -> SecretString {
    SecretString::from(["oauth", label, "passphrase"].join("-"))
}

/// A fresh random PKCE verifier (43 base64url characters).
fn verifier() -> Result<SecretString, Box<dyn Error>> {
    Ok(SecretString::from(random_text()?))
}

/// The S256 challenge of `verifier`.
fn challenge(verifier: &SecretString) -> Result<PkceChallenge, Box<dyn Error>> {
    let digest = Sha256::digest(verifier.expose_secret().as_bytes());
    Ok(PkceChallenge::parse(
        "S256",
        &URL_SAFE_NO_PAD.encode(digest),
    )?)
}

/// 32 random bytes as 43 base64url characters.
fn random_text() -> Result<String, Box<dyn Error>> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_error| "OS RNG")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
