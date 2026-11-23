//! The mTLS suite's `kcc serve` child and its state: roles, API keys, the uploaded client
//! CA and the server's TLS identity.

use core::time::Duration;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::Instant,
};

use kcc_app::{
    api_keys::{ApiKeysDocument, create_api_key, expose_created_key},
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
    secrets::MASTER_KEY_FILE_ENV,
};
use kcc_testkit::toml_text::path as toml_path;
use rustls::{crypto::ring::default_provider, pki_types::CertificateDer};
use tempfile::TempDir;

use crate::{
    TestResult, master_key,
    pki::{ClientCa, https, server_identity},
    serve_port::{Start, await_ready, start_on_free_ports, stderr_lines},
    spawning,
};

/// Upper bound for a start and for each awaited log line.
pub(crate) const LIMIT: Duration = Duration::from_secs(30);

/// The client certificates' common name, also the name of an admin API key.
pub(crate) const CN: &str = "laptop";

/// mTLS on both listeners: optional on main, required on the dedicated one (`DEDICATED`
/// stands for the dedicated port).
pub(crate) const SIGN_IN: &str = "[mcp.dedicated]\nenabled = true\nport = DEDICATED\n\n[mcp.auth.main]\nmtls = \"optional\"\n\n[mcp.auth.dedicated]\nmtls = \"required\"\n\n[mcp.auth.mtls]\ndefault_role = \"lab\"\n";

/// A `kcc serve` child; killed on drop.
pub(crate) struct Server {
    /// The process.
    child: Child,
    /// Its stderr lines.
    lines: mpsc::Receiver<String>,
    /// Every line read so far.
    seen: Vec<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Server {
    /// Reads lines until one contains `wanted`, for at most [`LIMIT`]; that line.
    pub(crate) fn until(&mut self, wanted: &str) -> TestResult<String> {
        if let Some(line) = self.seen.iter().find(|line| line.contains(wanted)) {
            return Ok(line.clone());
        }
        let deadline = Instant::now().checked_add(LIMIT).ok_or("deadline")?;
        loop {
            let line = self
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|error| {
                    format!("{error} waiting for {wanted:?}:\n{}", self.seen.join("\n"))
                })?;
            self.seen.push(line.clone());
            if line.contains(wanted) {
                return Ok(line);
            }
        }
    }
}

/// State with a custom role `lab` (read, write and destructive), the admin key [`CN`] and the
/// `lab` key, a client CA uploaded as `<state>/mcp/mtls-ca.pem`, and a TLS identity.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the tests present the uploaded CA's certificates and sign in with the keys"
)]
pub(crate) struct Fixture {
    /// Holds everything on disk.
    directory: TempDir,
    /// The uploaded client CA.
    pub(crate) ca: ClientCa,
    /// The admin key named like the client certificates.
    pub(crate) admin_key: String,
    /// A key of the `lab` role.
    pub(crate) lab_key: String,
    /// The server certificate and key files and the certificate's DER.
    tls: (PathBuf, PathBuf, CertificateDer<'static>),
}

impl Fixture {
    pub(crate) fn new() -> TestResult<Self> {
        let _installed = default_provider().install_default();
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        state.update(|roles: &mut RolesDocument| {
            roles.roles.push(Role::new(
                "lab".to_owned(),
                [Permission::Read, Permission::Write, Permission::Destructive],
                vec!["*".to_owned()],
            ));
        })?;
        let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
        let key = |name: &str, role: &str| {
            create_api_key(&state, &admin, name.to_owned(), role.to_owned(), 1, None)
                .map(|created| expose_created_key(&created).to_owned())
        };
        let (admin_key, lab_key) = (key(CN, "admin")?, key("lab-key", "lab")?);
        let ca = ClientCa::new("kcc test client CA")?;
        let mcp = state.dir().join("mcp");
        fs::create_dir_all(&mcp)?;
        fs::write(mcp.join("mtls-ca.pem"), ca.pem())?;
        master_key::write(&directory.path().join("master.key"), [17_u8; 32])?;
        let tls = server_identity(directory.path())?;
        Ok(Self {
            directory,
            ca,
            admin_key,
            lab_key,
            tls,
        })
    }

    /// The state directory.
    pub(crate) fn state(&self) -> TestResult<StateStore> {
        Ok(StateStore::open(&self.directory.path().join("state"))?)
    }

    /// Writes kcc.toml for TLS on `main`, `sign_in` (with `DEDICATED` replaced) after
    /// `[mcp]`.
    pub(crate) fn configure(
        &self,
        [main, dedicated]: [u16; 2],
        sign_in: &str,
    ) -> TestResult<PathBuf> {
        let config = self.directory.path().join("kcc.toml");
        let (cert, key, _der) = &self.tls;
        fs::write(
            &config,
            format!(
                "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {main}\nshutdown_timeout = \"1s\"\ntls_cert_path = {}\ntls_key_path = {}\n\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = true\ntoolsets = [\"core\", \"system-admin\"]\n\n{}\n[observability]\nlog_format = \"json\"\n\n[state]\ndir = {}\n",
                toml_path(cert),
                toml_path(key),
                sign_in.replace("DEDICATED", &dedicated.to_string()),
                toml_path(&self.directory.path().join("state"))
            ),
        )?;
        Ok(config)
    }

    /// `kcc serve --config <config>`, on Linux behind a 1 MiB main-thread stack.
    pub(crate) fn command(&self, config: &Path) -> TestResult<Command> {
        let home = self.directory.path();
        let kcc = env!("CARGO_BIN_EXE_kcc");
        let mut command = if cfg!(target_os = "linux") {
            let mut wrapped = spawning::command("sh");
            let _: &mut Command = wrapped.args(["-c", "ulimit -s 1024 && exec \"$0\" \"$@\"", kcc]);
            wrapped
        } else {
            spawning::command(kcc)
        };
        let _: &mut Command = command
            .args([
                "serve",
                "--config",
                config.to_str().ok_or("non-UTF-8 path")?,
            ])
            .env_clear()
            .envs(env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
            .env("PATH", env::var_os("PATH").unwrap_or_default())
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("state-home"))
            .env("LOCALAPPDATA", home.join("state-home"))
            .env("APPDATA", home.join("config"))
            .env(MASTER_KEY_FILE_ENV, home.join("master.key"))
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        Ok(command)
    }

    /// Starts `kcc serve` with `sign_in` and waits until the main listener serves; the
    /// main and dedicated ports and the server.
    pub(crate) fn serve(&self, sign_in: &str) -> TestResult<([u16; 2], Server)> {
        start_on_free_ports(|ports: [u16; 2]| -> TestResult<Start<Server>> {
            let config = self.configure(ports, sign_in)?;
            let mut child = spawning::spawn(&mut self.command(&config)?)?;
            let lines = stderr_lines(&mut child)?;
            let listening = format!("listening on 127.0.0.1:{}", ports[0]);
            Ok(
                match await_ready(&lines, |line| line.contains(&listening), LIMIT)? {
                    Start::Ready(seen) => Start::Ready(Server { child, lines, seen }),
                    Start::AddressInUse => Start::AddressInUse,
                },
            )
        })
    }

    /// Starts `kcc serve` with mTLS on both listeners and waits until both serve.
    pub(crate) fn serve_both(&self) -> TestResult<([u16; 2], Server)> {
        let (ports, mut server) = self.serve(SIGN_IN)?;
        let _line = server.until(&format!("listening on 127.0.0.1:{}", ports[1]))?;
        Ok((ports, server))
    }

    /// An HTTPS client presenting a certificate named [`CN`] from `ca`, or none.
    pub(crate) fn client(&self, ca: Option<&ClientCa>) -> TestResult<reqwest::Client> {
        let identity = ca.map(|issuer| issuer.client(CN)).transpose()?;
        https(&self.tls.2, identity.as_ref())
    }

    /// The `last_used_at` of the API key [`CN`].
    pub(crate) fn last_used(&self) -> TestResult<Option<u64>> {
        Ok(self
            .state()?
            .read::<ApiKeysDocument>()?
            .ok_or("no API keys")?
            .keys
            .into_iter()
            .find(|key| key.name == CN)
            .ok_or("no key")?
            .last_used_at)
    }
}

/// The base URL of a listener on `port`.
pub(crate) fn url(port: u16) -> String {
    format!("https://127.0.0.1:{port}")
}
