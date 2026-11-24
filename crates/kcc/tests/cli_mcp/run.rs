//! The `kcc` CLI over the sign-in fixture's state: its own `kcc.toml` with a `[cli]`
//! role, and grants made the way kcc's sign-in makes them.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use kcc_app::{
    accounts::{Clock, NewAccount, SystemClock},
    mcp_auth::{
        clients::{Client, ClientRegistration, ClientStore, ClientsDocument},
        grants::{Grant, GrantStore},
        pending::{AuthorizationRequest, CodeTarget, PendingStore, PkceChallenge},
    },
    permissions::{Permission, Role},
    secrets::MASTER_KEY_FILE_ENV,
};
use kcc_testkit::toml_text;
use secrecy::{ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};

use crate::{
    fixture::{Fixture, PASSWORD, TestResult},
    flow::base64url,
    spawning,
};

/// The resource of every seeded grant.
pub(crate) const RESOURCE: &str = "http://127.0.0.1:8443/mcp";

/// A clock standing still at its instant.
#[derive(Debug)]
struct Fixed(u64);

impl Clock for Fixed {
    fn unix_seconds(&self) -> u64 {
        self.0
    }
}

/// The sign-in fixture's directory: the state, the master key and the configurations.
pub(crate) fn home(fixture: &Fixture) -> TestResult<PathBuf> {
    Ok(fixture
        .state_dir()
        .parent()
        .ok_or("the state directory has a parent")?
        .to_path_buf())
}

/// Writes `cli-<role>.toml` acting as `role`, with `extra` appended; its path.
pub(crate) fn config(fixture: &Fixture, role: &str, extra: &str) -> TestResult<PathBuf> {
    let path = home(fixture)?.join(format!("cli-{role}.toml"));
    let text = format!(
        "[state]\ndir = {}\n\n[cli]\nrole = \"{role}\"\n{extra}",
        toml_text::path(&fixture.state_dir()),
    );
    fs::write(&path, text)?;
    Ok(path)
}

/// Runs `kcc --config <config> <args>` with `env`, stdin closed, on Linux behind a 1 MiB
/// main-thread stack.
pub(crate) fn kcc(
    fixture: &Fixture,
    config: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> TestResult<Output> {
    let home = home(fixture)?;
    let binary = env!("CARGO_BIN_EXE_kcc");
    let mut command = if cfg!(target_os = "linux") {
        let mut wrapped = spawning::command("sh");
        let _: &mut Command = wrapped.args(["-c", "ulimit -s 1024 && exec \"$0\" \"$@\"", binary]);
        wrapped
    } else {
        spawning::command(binary)
    };
    let _: &mut Command = command
        .arg("--config")
        .arg(config)
        .args(args)
        .env_clear()
        .envs(env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .env("HOME", &home)
        .env("USER", "tester")
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state-home"))
        .env("LOCALAPPDATA", home.join("state-home"))
        .env("APPDATA", home.join("config"))
        .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
        .env("LANG", "C")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(spawning::spawn(&mut command)?.wait_with_output()?)
}

/// The exit code of `output`.
pub(crate) fn code(output: &Output) -> Option<i32> {
    output.status.code()
}

/// Its stdout as text.
pub(crate) fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Its stderr as text.
pub(crate) fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Clients and grants over the fixture's state, as kcc's sign-in makes them.
pub(crate) struct Seed<'fixture> {
    /// The fixture.
    fixture: &'fixture Fixture,
    /// The clients.
    clients: ClientStore,
    /// Codes.
    pending: PendingStore,
    /// Grants.
    grants: GrantStore,
}

impl<'fixture> Seed<'fixture> {
    /// The stores over `fixture`'s state.
    pub(crate) fn new(fixture: &'fixture Fixture) -> TestResult<Self> {
        let state = fixture.state()?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        Ok(Self {
            clients: ClientStore::new(state.clone(), Arc::clone(&clock)),
            pending: PendingStore::new(Arc::clone(&clock)),
            grants: GrantStore::new(state, clock, Duration::from_hours(7 * 24)),
            fixture,
        })
    }

    /// Registers a client named `name` redirecting to `redirect`.
    pub(crate) fn client(&self, name: Option<&str>, redirect: &str) -> TestResult<Client> {
        let registration =
            ClientRegistration::new(name.map(str::to_owned), vec![redirect.to_owned()]);
        Ok(self.clients.register(&registration)?)
    }

    /// Creates the viewer account `name`, which may then hold grants.
    pub(crate) fn holder(&self, name: &str) -> TestResult {
        let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        let password = SecretString::from(PASSWORD);
        self.fixture.accounts()?.create(
            &admin,
            NewAccount::new(name.to_owned(), password, "viewer".to_owned()),
        )?;
        Ok(())
    }

    /// The grant `account`'s consent to `client` makes.
    pub(crate) fn grant(&self, client: &Client, account: &str) -> TestResult<Grant> {
        self.issue((&self.pending, &self.grants), client, account)
    }

    /// A grant of `account` to `client` that expired in 2001 and was never revoked.
    ///
    /// It was made at a fixed instant in 2001 and its refresh token expired an hour later.
    /// Seed it after every live grant (issuing purges grants that are not live at its
    /// instant).
    pub(crate) fn expired_grant(&self, client: &Client, account: &str) -> TestResult<Grant> {
        let then: Arc<dyn Clock> = Arc::new(Fixed(1_000_000_000));
        let pending = PendingStore::new(Arc::clone(&then));
        let grants = GrantStore::new(self.fixture.state()?, then, Duration::from_hours(1));
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
        let challenge = base64url(&Sha256::digest(verifier.expose_secret().as_bytes()))?;
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
            .fixture
            .accounts()?
            .fingerprint(account)?
            .ok_or("the account has a password")?;
        Ok(grants.issue(&authorized, &fingerprint)?.grant().clone())
    }

    /// Whether grant `id` is stored and not revoked.
    pub(crate) fn live(&self, id: &str) -> TestResult<bool> {
        Ok(self
            .fixture
            .grants()?
            .get(id)
            .is_some_and(|grant| !grant.is_revoked()))
    }

    /// The stored clients.
    pub(crate) fn clients(&self) -> TestResult<ClientsDocument> {
        Ok(self
            .fixture
            .state()?
            .read::<ClientsDocument>()?
            .unwrap_or_default())
    }

    /// The bytes of the grants and clients files, to prove a refusal changed nothing.
    pub(crate) fn files(&self) -> (Vec<u8>, Vec<u8>) {
        let dir = self.fixture.state_dir();
        let read = |name: &str| fs::read(dir.join(name)).unwrap_or_default();
        (
            read("mcp_oauth_grants.json"),
            read("mcp_oauth_clients.json"),
        )
    }

    /// The grants file as text.
    pub(crate) fn grants_text(&self) -> TestResult<String> {
        Ok(fs::read_to_string(
            self.fixture.state_dir().join("mcp_oauth_grants.json"),
        )?)
    }
}
