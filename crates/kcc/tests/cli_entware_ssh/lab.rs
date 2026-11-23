//! Both fakes behind one hermetic CLI environment: the router `lab-1` and its Entware SSH
//! server, whose root password is random and lives in an owner-only file.

use core::hash::BuildHasher as _;
use std::{collections::hash_map::RandomState, path::PathBuf};

use kcc_i18n::{bundle::MessageKey, keys};
use kcc_testkit::entware_ssh::{Config, Counters, FakeEntwareSsh, Handle};
use serde_json::Value;

use super::{
    base::{self, Lab},
    support::{Run, TestResult, router},
};

/// The router id of the lab.
pub(crate) const ROUTER: &str = "lab-1";

/// The confirmation every SSH command needs.
pub(crate) const CONFIRM: [&str; 2] = ["--confirm-destructive", ROUTER];

/// Raw SSH output of the fake that must never reach the CLI's output.
const RAW: [&str; 4] = [
    "Updated list of available packages",
    "Collected errors",
    "alive.",
    "dead.",
];

/// A random lowercase hex marker, built at run time.
pub(crate) fn marker() -> String {
    format!(
        "{:016x}{:016x}",
        RandomState::new().hash_one(1_u8),
        RandomState::new().hash_one(2_u8)
    )
}

/// `key` in English with `args`.
pub(crate) fn en(key: MessageKey, args: &[(&'static str, &str)]) -> String {
    base::en(key, args)
}

/// The fake router, the fake Entware SSH server and the CLI environment.
pub(crate) struct SshLab {
    /// The fake router and the CLI environment.
    pub base: Lab,
    /// The fake Entware SSH server.
    pub ssh: Handle,
    /// Its port.
    pub port: u16,
    /// The Entware root password.
    pub password: String,
    /// The owner-only file holding it.
    pub password_file: PathBuf,
}

impl SshLab {
    /// Both fakes, the SSH one from `config` with a random password, for the CLI role
    /// `role`.
    pub(crate) async fn spawn(role: &str, config: Config) -> TestResult<Self> {
        let password = marker();
        let (address, ssh) = FakeEntwareSsh::spawn(config.password(password.as_str())).await?;
        let base = Lab::spawn(role).await?;
        let password_file = base.env.write("entware.password", &password)?;
        Ok(Self {
            base,
            ssh,
            port: address.port(),
            password,
            password_file,
        })
    }

    /// An administrator lab over an empty Entware userland.
    pub(crate) async fn admin() -> TestResult<Self> {
        Self::spawn("admin", Config::default()).await
    }

    /// Switches the CLI role to `role`.
    pub(crate) fn role(&self, role: &str) -> TestResult {
        let password = self.base.env.path("router.password");
        self.base.env.write_config(&format!(
            "[cli]\nrole = {role:?}\n\n{}",
            router(ROUTER, self.base.address, &password)
        ))
    }

    /// Runs `kcc <args>` and checks its output for secrets and raw SSH output.
    pub(crate) fn run(&self, args: &[&str]) -> TestResult<Run> {
        let run = self.base.run(args)?;
        self.assert_clean(&run);
        Ok(run)
    }

    /// Runs `kcc --confirm-destructive lab-1 <args>`.
    pub(crate) fn confirmed(&self, args: &[&str]) -> TestResult<Run> {
        self.run(&[&CONFIRM[..], args].concat())
    }

    /// Runs `kcc --json --confirm-destructive lab-1 <args>`, requires exit 0 and returns
    /// the one JSON document.
    pub(crate) fn json(&self, args: &[&str]) -> TestResult<Value> {
        let run = self.run(&[&["--json"][..], &CONFIRM[..], args].concat())?;
        assert_eq!(run.code, 0_i32, "kcc {args:?}: {run:?}");
        Ok(serde_json::from_str(&run.stdout)?)
    }

    /// Asserts that `run` carries neither the Entware password, a private key, kcc's key
    /// line nor raw SSH output.
    pub(crate) fn assert_clean(&self, run: &Run) {
        let authorized = self.ssh.authorized_keys();
        let lines = authorized
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1))
            .collect::<Vec<_>>();
        for text in [&run.stdout, &run.stderr] {
            assert!(!text.contains(&self.password), "password printed: {run:?}");
            assert!(!text.contains("PRIVATE KEY"), "key printed: {run:?}");
            for line in &lines {
                assert!(!text.contains(line), "kcc's key line printed: {run:?}");
            }
            for raw in RAW {
                assert!(!text.contains(raw), "raw SSH output printed: {run:?}");
            }
        }
    }

    /// Router requests and SSH activity so far.
    pub(crate) fn contacts(&self) -> (u64, Counters) {
        (self.base.fake.request_count(), self.ssh.counters())
    }

    /// `kcc entware ssh enable --port <the fake's port>`, which must succeed.
    pub(crate) fn enable(&self) -> TestResult<Value> {
        let port = self.port.to_string();
        self.json(&["entware", "ssh", "enable", "--port", &port])
    }

    /// `kcc entware ssh probe`: the ticket and the fingerprint.
    pub(crate) fn probe(&self) -> TestResult<(String, String)> {
        let probe = self.json(&["entware", "ssh", "probe"])?;
        let field = |name: &str| {
            probe
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("probe without {name}: {probe}"))
        };
        Ok((field("ticket")?, field("fingerprint")?))
    }

    /// `kcc entware ssh <step> --ticket <ticket> --fingerprint <fingerprint>` with the
    /// password file and `extra` global options.
    pub(crate) fn step(
        &self,
        step: &str,
        (ticket, fingerprint): (&str, &str),
        extra: &[&str],
    ) -> TestResult<Run> {
        let file = self.password_file.to_str().ok_or("non-UTF-8 path")?;
        let args = [
            &CONFIRM[..],
            &["--password-file", file],
            extra,
            &["entware", "ssh", step, "--ticket", ticket],
            &["--fingerprint", fingerprint],
        ]
        .concat();
        self.run(&args)
    }

    /// Enables, probes and bootstraps; the enrolment must succeed.
    pub(crate) fn enrol(&self) -> TestResult {
        drop(self.enable()?);
        let (ticket, fingerprint) = self.probe()?;
        let run = self.step("bootstrap", (&ticket, &fingerprint), &[])?;
        assert_eq!(run.code, 0_i32, "bootstrap: {run:?}");
        Ok(())
    }

    /// Stops both fakes.
    pub(crate) async fn shutdown(self) -> TestResult {
        self.ssh.shutdown().await?;
        self.base.shutdown().await
    }
}

/// Asserts that `run` failed with `code` and the English `key` with `args` on stderr.
pub(crate) fn refused(run: &Run, code: i32, key: MessageKey, args: &[(&'static str, &str)]) {
    assert_eq!(run.code, code, "{run:?}");
    let text = en(key, args);
    assert!(run.stderr.contains(&text), "expected {text:?}: {run:?}");
}

/// The refusal of an unconfirmed command on the lab router.
pub(crate) fn unconfirmed(run: &Run) {
    refused(
        run,
        10_i32,
        keys::CLI_CONFIRM_MISSING,
        &[("router", ROUTER)],
    );
}
