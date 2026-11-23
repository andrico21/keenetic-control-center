//! Hermetic fakes behind the live contract: a KN-1811 fake router (with an `ext4` fixture
//! drive) and, for the SSH suite, the fake Entware SSH server; plus the log capture the
//! skip proofs read.

use alloc::{collections::BTreeMap, sync::Arc};
use core::error::Error;
use std::{fs, io, sync::Mutex};

use kcc_rci::{RciBody, RciPath};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle,
    capture::connect,
    entware_ssh::{self, Config, FakeEntwareSsh},
    migration,
    model::{Firmware, Model, Profile},
    toml_text,
};
use secrecy::SecretString;
use serde_json::json;
use tempfile::TempDir;
use tracing::subscriber::set_default;
use tracing_subscriber::fmt::MakeWriter;

use super::{Reach, TestResult};

/// The fixture drive `kcc entware status` lists as eligible.
pub(crate) const DRIVE: &str = "fixture-media:/";

/// The fake Entware SSH server of a lab.
pub(crate) struct Ssh {
    /// Its handle.
    pub handle: entware_ssh::Handle,
    /// Its port.
    pub port: u16,
}

/// One fake router with its kcc configuration, password files and evidence directory.
pub(crate) struct Lab {
    /// Temporary files.
    pub directory: TempDir,
    /// Router origin.
    pub url: String,
    /// Router handle.
    pub handle: Handle,
    /// The fake router's serial.
    pub serial: String,
    /// The running configuration at start.
    pub config: String,
    /// The fake Entware SSH server, when started.
    pub ssh: Option<Ssh>,
}

impl Lab {
    /// Starts the fake router; its profile has `test_device = test_device`.
    // NOT cancel-safe: starts a background router and writes temporary files.
    pub(crate) async fn start(test_device: bool) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let version = json!({
            "title": Firmware::V5_1.title(), "release": Firmware::V5_1.release(),
            "model": "Keenetic", "device": "Keenetic", "hw_id": "KN-1811",
            "hw_version": "10000000", "hw_type": "router", "arch": "aarch64",
            "ndw": {"components": "base,usb,storage,opkg,ext", "features": "wifi2ghz"}
        });
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        let (address, handle) = FakeRouter::builder(Profile::latest(Model::Kn1811))
            .show_fixture("version", version)
            .reached_directly()
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let url = format!("http://{address}");
        let password_file =
            kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
        fs::write(
            directory.path().join("kcc.toml"),
            format!(
                "[outbound]\nallow_loopback = true\nallowed_networks = [\"198.51.100.0/24\"]\n\n[[routers]]\nname = \"lab\"\nurl = \"{url}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = {}\ntest_device = {test_device}\n",
                toml_text::path(&password_file)
            ),
        )?;
        let serial = serial(&url).await?;
        let config = handle.running_config_text();
        Ok(Self {
            directory,
            url,
            handle,
            serial,
            config,
            ssh: None,
        })
    }

    /// Adds a fake Entware SSH server from `config` whose root password is `password` and
    /// writes the password to the lab's `entware.password`.
    // NOT cancel-safe: starts a background server and writes a temporary file.
    pub(crate) async fn with_ssh(mut self, config: Config, password: &str) -> TestResult<Self> {
        let (address, handle) = FakeEntwareSsh::spawn(config.password(password)).await?;
        drop(kcc_testkit::write_secret_file(
            self.directory.path(),
            "entware.password",
            password,
        )?);
        self.ssh = Some(Ssh {
            handle,
            port: address.port(),
        });
        Ok(self)
    }

    /// Every contract variable pointing at this lab, with `changes` applied (an empty
    /// value removes the variable).
    pub(crate) fn env(&self, changes: &[(&str, &str)]) -> BTreeMap<String, String> {
        let root = self.directory.path();
        let path = |name: &str| root.join(name).display().to_string();
        let mut vars = BTreeMap::from([
            ("KCC_LIVE_URL".to_owned(), self.url.clone()),
            ("KCC_LIVE_LOGIN".to_owned(), DEFAULT_LOGIN.to_owned()),
            ("KCC_LIVE_PASSWORD_FILE".to_owned(), path("password")),
            ("KCC_LIVE_ALLOW_SERIAL".to_owned(), self.serial.clone()),
            ("KCC_LIVE_TARGET_CONFIG".to_owned(), path("kcc.toml")),
            ("KCC_LIVE_ALLOW_WRITE".to_owned(), "1".to_owned()),
            ("KCC_LIVE_ENTWARE_SETUP".to_owned(), "1".to_owned()),
            ("KCC_LIVE_ENTWARE_DRIVE".to_owned(), DRIVE.to_owned()),
            (
                "KCC_LIVE_ENTWARE_PASSWORD_FILE".to_owned(),
                path("entware.password"),
            ),
        ]);
        for &(name, value) in changes {
            if value.is_empty() {
                drop(vars.remove(name));
            } else {
                drop(vars.insert(name.to_owned(), value.to_owned()));
            }
        }
        vars
    }

    /// Where a hermetic run reaches the fakes and writes its evidence.
    pub(crate) fn reach(&self) -> Reach {
        Reach {
            evidence: self.directory.path().join("evidence"),
            allow_loopback: true,
            ssh_ports: self.ssh.iter().map(|ssh| ssh.port).collect(),
        }
    }

    /// What could have changed the router: every request carrying a parser line, every
    /// method other than GET and POST (a structured root POST is a `show` tree), and a
    /// running configuration that differs from the one at start.
    pub(crate) fn writes(&self) -> Vec<String> {
        let mut writes = self
            .handle
            .request_log()
            .iter()
            .filter(|record| {
                record.commands().next().is_some()
                    || !(record.method() == "GET" || record.method() == "POST")
            })
            .map(|record| format!("{} {}", record.method(), record.path()))
            .collect::<Vec<_>>();
        if self.handle.running_config_text() != self.config {
            writes.push("running configuration changed".to_owned());
        }
        writes
    }

    /// Every parser line the router received, in order.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.handle
            .request_log()
            .iter()
            .flat_map(|record| {
                record
                    .commands()
                    .flatten()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Stops the fakes.
    pub(crate) async fn shutdown(self) -> TestResult {
        if let Some(ssh) = self.ssh {
            ssh.handle.shutdown().await?;
        }
        self.handle.shutdown().await?;
        Ok(())
    }
}

/// Reads the fake router serial.
// cancel-safe: one read.
async fn serial(url: &str) -> Result<String, Box<dyn Error>> {
    let connection = connect(
        url.parse()?,
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
        true,
    )
    .await?;
    let path = RciPath::from_segments(["show", "identification"])?;
    let RciBody::Json(response) = connection.client.get(&path, &()).await? else {
        return Err("expected JSON identification".into());
    };
    Ok(response
        .value
        .get("serial")
        .and_then(serde_json::Value::as_str)
        .ok_or("fake router has no serial")?
        .to_owned())
}

/// Collects the log lines of the test thread.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_poison| io::Error::other("log buffer poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Captured {
    type Writer = Self;

    fn make_writer(&self) -> Self {
        self.clone()
    }
}

/// Runs `run` with a subscriber that records the test thread's log lines; returns the
/// outcome and the log text.
// NOT cancel-safe: dropping it drops `run` midway.
pub(crate) async fn logged<F>(run: F) -> Result<(TestResult, String), Box<dyn Error>>
where
    F: Future<Output = TestResult>,
{
    let log = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    let guard = set_default(subscriber);
    let outcome = run.await;
    drop(guard);
    let text = String::from_utf8(
        log.0
            .lock()
            .map_err(|_poison| "log buffer poisoned")?
            .clone(),
    )?;
    Ok((outcome, text))
}
