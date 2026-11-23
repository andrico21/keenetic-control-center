//! Todo 16: the router-side refusals of the domain, each with its pinned exit code: a busy
//! router, `opkg chroot` on, SSH management switched off, and a read that does not
//! answer in time.

use std::thread;

use kcc_app::{
    entware_ssh::state::SshStore,
    persist::{StateLock, StateStore},
    secrets::MasterKey,
};
use kcc_i18n::keys;
use kcc_testkit::entware_ssh::{Config, Fault, Service};
use serde_json::json;

use super::{
    lab::{ROUTER, SshLab, refused},
    support::{Run, TestResult},
};

/// The userland of these tests.
fn userland() -> Config {
    Config::default()
        .installed("curl", "8.0-1")
        .service("S80nginx", Service::new("nginx"))
}

/// Holds the lab router's write lease in the test process, as a running setup job would.
fn hold_lease(lab: &SshLab) -> TestResult<StateLock> {
    Ok(StateStore::open(&lab.base.env.state_dir())?.try_lease(ROUTER)?)
}

/// Todo 16: while another holder has the router write lease (a setup job), every command
/// that takes it exits 5 with the localized busy message and sends no password.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_router_exits_5() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    lab.enrol()?;
    let (ticket, fingerprint) = lab.probe()?;
    let port = lab.port.to_string();
    let lease = hold_lease(&lab)?;
    let attempts = lab.ssh.counters().password_attempts;
    let mut runs = Vec::new();
    for args in [
        &["entware", "ssh", "enable", "--port", &port][..],
        &["entware", "ssh", "disable"][..],
        &["entware", "ssh", "revoke"][..],
        &["entware", "packages", "update"][..],
        &["entware", "packages", "install", "curl"][..],
        &["entware", "packages", "remove", "curl"][..],
        &["entware", "packages", "upgrade", "curl"][..],
        &["entware", "services", "start", "S80nginx"][..],
        &["entware", "services", "stop", "S80nginx"][..],
        &["entware", "services", "restart", "S80nginx"][..],
    ] {
        runs.push(lab.confirmed(args)?);
    }
    for step in ["bootstrap", "repin"] {
        runs.push(lab.step(step, (&ticket, &fingerprint), &["--yes"])?);
    }

    for run in &runs {
        refused(
            run,
            5_i32,
            keys::CLI_ENTWARE_SSH_BUSY,
            &[("router", ROUTER)],
        );
    }
    assert_eq!(lab.ssh.counters().password_attempts, attempts);
    drop(lease);
    let bootstrap = lab.step("bootstrap", (&ticket, &fingerprint), &["--yes"])?;
    assert_eq!(bootstrap.code, 0_i32, "the ticket survived: {bootstrap:?}");
    lab.shutdown().await
}

/// Todo 16: with `opkg chroot` on, every command that would open an SSH connection exits
/// 10 without one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chroot_on_exits_10_without_a_connection() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    lab.enrol()?;
    assert!(lab.base.fake.configure("opkg chroot"));
    let connections = lab.ssh.counters().connections;
    for args in [
        &["entware", "ssh", "probe"][..],
        &["entware", "ssh", "revoke"][..],
        &["entware", "packages", "list"][..],
        &["entware", "packages", "upgradable"][..],
        &["entware", "packages", "update"][..],
        &["entware", "packages", "install", "curl"][..],
        &["entware", "services", "list"][..],
        &["entware", "services", "status", "S80nginx"][..],
        &["entware", "services", "start", "S80nginx"][..],
    ] {
        let run = lab.confirmed(args)?;

        refused(
            &run,
            10_i32,
            keys::CLI_ENTWARE_SSH_CHROOT,
            &[("router", ROUTER)],
        );
    }
    assert_eq!(lab.ssh.counters().connections, connections);
    lab.shutdown().await
}

/// Todo 16: with SSH management switched off, operations exit 10 without a connection;
/// `ssh enable` switches it on again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn switched_off_ssh_exits_10_until_enabled() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    lab.enrol()?;
    let store = SshStore::new(
        StateStore::open(&lab.base.env.state_dir())?,
        MasterKey::from_bytes([17_u8; 32]),
    );
    drop(store.set_enabled(ROUTER, false)?);
    let connections = lab.ssh.counters().connections;

    let list = lab.confirmed(&["entware", "packages", "list"])?;
    let start = lab.confirmed(&["entware", "services", "start", "S80nginx"])?;

    for run in [&list, &start] {
        refused(
            run,
            10_i32,
            keys::CLI_ENTWARE_SSH_DISABLED,
            &[("router", ROUTER)],
        );
    }
    assert_eq!(lab.ssh.counters().connections, connections);
    let port = lab.port.to_string();
    let enabled = lab.json(&["entware", "ssh", "enable", "--port", &port])?;
    assert_eq!(
        enabled,
        json!({"router": ROUTER, "enabled": true, "port": lab.port, "state": "active"})
    );
    let listed = lab.json(&["entware", "packages", "list"])?;
    assert_eq!(
        listed,
        json!({"packages": [{"name": "curl", "version": "8.0-1", "new_version": null}]})
    );
    lab.shutdown().await
}

/// Todo 16: a read the router never answers ends with the localized 'slow or busy'
/// failure (exit 5) before kcc-ssh's own read timeout, for every read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unanswered_read_exits_5_in_time() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    lab.enrol()?;
    lab.ssh.set_fault(Some(Fault::Hang));
    let reads = [
        &["entware", "packages", "list"][..],
        &["entware", "packages", "upgradable"][..],
        &["entware", "services", "list"][..],
        &["entware", "services", "status", "S80nginx"][..],
    ];

    let runs = thread::scope(|scope| {
        let handles = reads
            .map(|args| scope.spawn(|| lab.confirmed(args).map_err(|error| error.to_string())));
        handles.map(|handle| handle.join().map_err(|_panic| "reader panicked".to_owned()))
    });

    for joined in runs {
        let run: Run = joined??;
        refused(
            &run,
            5_i32,
            keys::CLI_ENTWARE_SSH_SLOW,
            &[("router", ROUTER)],
        );
    }
    lab.shutdown().await
}
