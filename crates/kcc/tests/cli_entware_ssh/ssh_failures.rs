//! Todo 16: the SSH-side failures the other tests leave open, each with its exit code.
//!
//! A router URL whose host changed since the enrolment, an SSH connection that is
//! refused or dropped, and a revoke the router's SSH server refuses.

use std::net::TcpListener;

use kcc_app::{entware_ssh::state::SshStore, persist::StateStore, secrets::MasterKey};
use kcc_i18n::keys;
use kcc_testkit::entware_ssh::{Config, Fault, Service};

use super::{
    lab::{ROUTER, SshLab, en, refused},
    support::{Run, TestResult},
};

/// The userland of these tests.
fn userland() -> Config {
    Config::default()
        .installed("curl", "8.0-1")
        .installable("nano", "7.2-1")
        .service("S80nginx", Service::new("nginx"))
}

/// Points the profile of the lab router at `host` (same port, same password file).
fn point(lab: &SshLab, host: &str) -> TestResult {
    let password = lab.base.env.path("router.password").display().to_string();
    let port = lab.base.address.port();
    lab.base.env.write_config(&format!(
        "[cli]\nrole = \"admin\"\n\n[[routers]]\nname = {ROUTER:?}\n\
         url = \"http://{host}:{port}\"\nlogin = \"admin\"\npassword_file = {password:?}\n\n"
    ))
}

/// Asserts that `run` failed with `code` and the generic headline of that exit class.
fn failed_with(run: &Run, code: i32, headline: &str) {
    assert_eq!(run.code, code, "{run:?}");
    assert!(
        run.stderr.contains(headline),
        "expected {headline:?}: {run:?}"
    );
}

/// Todo 16: after the router URL's host changed (`127.0.0.1` to `localhost`), every SSH
/// command exits 5 with `host-changed` before any SSH contact, so no password, key or
/// command reaches the Entware server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_router_host_exits_5_without_ssh_contact() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    for args in [
        &["entware", "ssh", "probe"][..],
        &["entware", "ssh", "revoke"][..],
        &["entware", "packages", "list"][..],
        &["entware", "packages", "install", "nano"][..],
        &["entware", "services", "start", "S80nginx"][..],
    ] {
        point(&lab, "127.0.0.1")?;
        lab.enrol()?;
        point(&lab, "localhost")?;
        let before = lab.ssh.counters();

        let run = lab.confirmed(args)?;

        refused(
            &run,
            5_i32,
            keys::CLI_ENTWARE_SSH_HOST_CHANGED,
            &[("router", ROUTER)],
        );
        assert_eq!(lab.ssh.counters(), before, "{args:?}: SSH contact");
    }
    assert!(!lab.ssh.installed().contains_key("nano"));
    lab.shutdown().await
}

/// Todo 16: an SSH failure outside the classified ones exits 6 with the router headline.
///
/// A connection dropped on its first command (a read, and a change whose listing is
/// dropped) and a connection the SSH port refuses. No password is sent and the change is
/// not applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_ssh_failures_exit_6() -> TestResult {
    let lab = SshLab::spawn("admin", userland()).await?;
    lab.enrol()?;
    let attempts = lab.ssh.counters().password_attempts;
    lab.ssh
        .set_fault(Some(Fault::KillAfter(lab.ssh.counters().commands)));
    let mut runs = vec![
        lab.confirmed(&["entware", "packages", "list"])?,
        lab.confirmed(&["entware", "packages", "install", "nano"])?,
    ];
    lab.ssh.set_fault(None);
    let closed = TcpListener::bind(("127.0.0.1", 0))?.local_addr()?.port();
    drop(lab.json(&["entware", "ssh", "enable", "--port", &closed.to_string()])?);

    runs.push(lab.confirmed(&["entware", "services", "start", "S80nginx"])?);

    let router = en(keys::CLI_ERROR_ROUTER, &[]);
    for run in &runs {
        failed_with(run, 6_i32, &router);
    }
    assert!(!lab.ssh.installed().contains_key("nano"));
    assert_eq!(lab.ssh.counters().password_attempts, attempts);
    lab.shutdown().await
}

/// Todo 16: a revoke the SSH server refuses (its host key changed) exits 6 with the
/// router headline and sends no password; kcc's key line and the local enrolment stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_revoke_exits_6_and_keeps_the_enrolment() -> TestResult {
    let lab = SshLab::admin().await?;
    lab.enrol()?;
    drop(lab.ssh.replace_host_key());
    let attempts = lab.ssh.counters().password_attempts;

    let run = lab.confirmed(&["entware", "ssh", "revoke"])?;

    failed_with(&run, 6_i32, &en(keys::CLI_ERROR_ROUTER, &[]));
    assert_eq!(lab.ssh.counters().password_attempts, attempts);
    assert!(lab.ssh.authorized_keys().contains("kcc:lab-1"));
    let store = SshStore::new(
        StateStore::open(&lab.base.env.state_dir())?,
        MasterKey::from_bytes([17_u8; 32]),
    );
    assert!(store.load(ROUTER)?.is_some(), "the enrolment was kept");
    assert!(store.load_key(ROUTER)?.is_some(), "kcc's key was kept");
    lab.shutdown().await
}
