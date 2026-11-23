//! Owner-run live suites for Entware, plus hermetic proofs of their refusals.
//!
//! The live tests are `#[ignore]`d; run them one at a time with
//! `cargo test -p kcc --test live_entware -- --ignored --exact <name>`:
//!
//! - `live_entware_probe` (read-only): records `show media` (label, uuid,
//!   `initialize-supported`), `components list`, `show rc` `opkg`, `show version` `arch`,
//!   `kcc entware status` and the shape of a short `show log` reply in
//!   `.omo/evidence/live-entware-probe.json`.
//! - `live_entware_setup` (`KCC_LIVE_ALLOW_WRITE=1`, `KCC_LIVE_ENTWARE_SETUP=1`,
//!   `KCC_LIVE_ENTWARE_DRIVE`): refuses unless the drive is one of the router's eligible
//!   drives, runs `kcc entware setup` on it and records the job and the installer's log
//!   markers in `.omo/evidence/live-entware-setup.json`. It never saves.
//! - `live_entware_ssh` (`KCC_LIVE_ALLOW_WRITE=1`, `KCC_LIVE_ENTWARE_PASSWORD_FILE`,
//!   optional `KCC_LIVE_ENTWARE_PACKAGE`, default `nano`): probes port 222, then 22,
//!   bootstraps, lists, installs and removes the package, checks one service and always
//!   revokes; records `.omo/evidence/live-entware-ssh.json`.
//!
//! Every suite needs `KCC_LIVE_URL`, `KCC_LIVE_LOGIN`, `KCC_LIVE_PASSWORD_FILE`,
//! `KCC_LIVE_ALLOW_SERIAL` and `KCC_LIVE_TARGET_CONFIG` (its `[[routers]]` entry for
//! `KCC_LIVE_URL` has `test_device = true`); a missing variable logs `live-skip:<reason>`
//! and returns `Ok(())`. The profile is checked before the router is contacted, the serial
//! right after. The suites drive the built `kcc` with a temporary home whose only router
//! profile is the admitted one, under the admitted configuration's `[outbound]` table.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

extern crate alloc;

#[path = "live_entware/admit.rs"]
mod admit;
#[path = "live_entware/cleanup.rs"]
mod cleanup;
#[path = "live_entware/contract.rs"]
mod contract;
#[path = "live_entware/evidence.rs"]
mod evidence;
#[path = "live_entware/lab.rs"]
mod lab;
#[path = "support/live_gate.rs"]
mod live_gate;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "live_entware/probe.rs"]
mod probe;
#[path = "live_entware/refusal.rs"]
mod refusal;
#[path = "live_entware/setup.rs"]
mod setup;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "live_entware/ssh.rs"]
mod ssh;
#[path = "live_entware/twins.rs"]
mod twins;

use core::error::Error;
use std::{env, io, path::PathBuf};

/// Fallible test result.
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Where a run reaches the router and writes its evidence.
pub(crate) struct Reach {
    /// Evidence directory.
    pub evidence: PathBuf,
    /// Admit a loopback router (the hermetic fakes only).
    pub allow_loopback: bool,
    /// Entware SSH ports tried in order.
    pub ssh_ports: Vec<u16>,
}

impl Reach {
    /// The owner's run: the workspace evidence directory, no loopback, ports 222 then 22.
    fn live() -> Self {
        Self {
            evidence: evidence::workspace(),
            allow_loopback: false,
            ssh_ports: vec![222, 22],
        }
    }
}

/// Reads the process environment.
fn environment(name: &str) -> Option<String> {
    env::var(name).ok()
}

/// Logs to stderr for the owner's run.
fn trace() {
    drop(tracing_subscriber::fmt().with_writer(io::stderr).try_init());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live router: needs KCC_LIVE_* and a test_device router"]
async fn live_entware_probe() -> TestResult {
    trace();
    probe::run(&environment, &Reach::live()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live router: installs Entware on KCC_LIVE_ENTWARE_DRIVE of a test_device router"]
async fn live_entware_setup() -> TestResult {
    trace();
    setup::run(&environment, &Reach::live()).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "live router: enrols kcc's key on a test_device router's Entware and revokes it"]
async fn live_entware_ssh() -> TestResult {
    trace();
    ssh::run(&environment, &Reach::live()).await
}
