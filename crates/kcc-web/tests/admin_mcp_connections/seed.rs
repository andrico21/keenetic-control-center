//! Clients and grants written straight into the page's state directory, as kcc's sign-in
//! would make them, at the fixture's frozen instant.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::fs;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use kcc_app::{
    accounts::{AccountStore, Clock, NewAccount},
    mcp_auth::{
        clients::{Client, ClientRegistration, ClientStore, ClientsDocument},
        grants::{Grant, GrantStore, GrantsDocument},
        pending::{AuthorizationRequest, CodeTarget, PendingStore, PkceChallenge},
    },
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
};
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

use crate::support::outcome::TestResult;

/// The instant of the Web UI fixture's frozen clock.
pub(crate) const NOW: u64 = 1_700_000_000;

/// The MCP resource every seeded grant is for.
pub(crate) const RESOURCE: &str = "http://127.0.0.1:8443/mcp";

/// The accounts that hold seeded grants.
pub(crate) const HOLDERS: [&str; 3] = ["alice", "bob", "carol"];

/// A clock standing still at its instant.
#[derive(Debug)]
struct Fixed(u64);

impl Clock for Fixed {
    fn unix_seconds(&self) -> u64 {
        self.0
    }
}

/// A clock standing at [`NOW`], for a store a test drives itself.
pub(crate) fn clock() -> Arc<dyn Clock> {
    Arc::new(Fixed(NOW))
}

/// The stores of kcc's sign-in over a state directory.
pub(crate) struct Seed {
    /// The state directory.
    state: StateStore,
    /// The grant holders' accounts, under a key of their own.
    accounts: AccountStore,
    /// The role that creates the holders' accounts.
    admin: Role,
    /// The clients.
    clients: ClientStore,
    /// Codes.
    pending: PendingStore,
    /// Grants.
    grants: GrantStore,
}

impl Seed {
    /// The stores over `state`, with the accounts of [`HOLDERS`] (viewers).
    pub(crate) fn new(state: &StateStore) -> TestResult<Self> {
        let clock = clock();
        let accounts = AccountStore::new(
            state.clone(),
            MasterKey::from_bytes([9_u8; 32]),
            Duration::from_mins(1),
            Arc::clone(&clock),
        );
        let seed = Self {
            clients: ClientStore::new(state.clone(), Arc::clone(&clock)),
            pending: PendingStore::new(Arc::clone(&clock)),
            grants: GrantStore::new(state.clone(), clock, Duration::from_hours(7 * 24)),
            state: state.clone(),
            accounts,
            admin: Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
        };
        for name in HOLDERS {
            seed.holder(name)?;
        }
        Ok(seed)
    }

    /// Creates the viewer account `name`, which may then hold grants.
    pub(crate) fn holder(&self, name: &str) -> TestResult {
        let password = SecretString::from(["grant", name, "passphrase"].join("-"));
        self.accounts.create(
            &self.admin,
            NewAccount::new(name.to_owned(), password, "viewer".to_owned()),
        )?;
        Ok(())
    }

    /// Registers a dynamic client named `name` redirecting to `redirect`.
    pub(crate) fn client(&self, name: Option<&str>, redirect: &str) -> TestResult<Client> {
        let registration =
            ClientRegistration::new(name.map(str::to_owned), vec![redirect.to_owned()]);
        Ok(self.clients.register(&registration)?)
    }

    /// Connects `account` to `client`: the grant its consent makes.
    pub(crate) fn grant(&self, client: &Client, account: &str) -> TestResult<Grant> {
        self.issue((&self.pending, &self.grants), client, account)
    }

    /// A grant of `account` to `client` that expired before [`NOW`] and was never revoked.
    ///
    /// It was made two hours before [`NOW`] and its refresh token expired an hour later.
    /// Seed it after every live grant (issuing purges grants that are not live at the
    /// issuer's instant).
    pub(crate) fn expired_grant(&self, client: &Client, account: &str) -> TestResult<Grant> {
        let then: Arc<dyn Clock> = Arc::new(Fixed(1_699_992_800));
        let pending = PendingStore::new(Arc::clone(&then));
        let grants = GrantStore::new(self.state.clone(), then, Duration::from_hours(1));
        self.issue((&pending, &grants), client, account)
    }

    /// The grant `account`'s consent to `client` makes through `pending` and `grants`.
    fn issue(
        &self,
        (pending, grants): (&PendingStore, &GrantStore),
        client: &Client,
        account: &str,
    ) -> TestResult<Grant> {
        let verifier = SecretString::from(format!("{account}-{}", client.id()));
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose_secret().as_bytes()));
        let redirect = client.redirect_uris().first().ok_or("a redirect URI")?;
        let target = CodeTarget::new(client.id(), redirect, RESOURCE);
        let request = AuthorizationRequest::new(
            client,
            target.clone(),
            PkceChallenge::parse("S256", &challenge)?,
        )?;
        let code = pending.issue_code(request, account)?;
        let authorized = pending.redeem(&code, &target, &verifier)?;
        let fingerprint = self
            .accounts
            .fingerprint(account)?
            .ok_or("the account has a password")?;
        Ok(grants.issue(&authorized, &fingerprint)?.grant().clone())
    }

    /// The stored grants.
    pub(crate) fn grants(&self) -> TestResult<GrantsDocument> {
        Ok(self.state.read::<GrantsDocument>()?.unwrap_or_default())
    }

    /// Whether grant `id` is stored and not revoked.
    pub(crate) fn live(&self, id: &str) -> TestResult<bool> {
        Ok(self
            .grants()?
            .get(id)
            .is_some_and(|grant| !grant.is_revoked()))
    }

    /// The stored clients.
    pub(crate) fn clients(&self) -> TestResult<ClientsDocument> {
        Ok(self.state.read::<ClientsDocument>()?.unwrap_or_default())
    }

    /// The bytes of the grants and clients files, to prove a refusal changed nothing.
    pub(crate) fn files(&self) -> (Vec<u8>, Vec<u8>) {
        let read = |name: &str| fs::read(self.state.dir().join(name)).unwrap_or_default();
        (
            read("mcp_oauth_grants.json"),
            read("mcp_oauth_clients.json"),
        )
    }

    /// The raw bytes of the grants file, to look for its hashes elsewhere.
    pub(crate) fn grants_text(&self) -> TestResult<String> {
        Ok(fs::read_to_string(
            self.state.dir().join("mcp_oauth_grants.json"),
        )?)
    }
}
