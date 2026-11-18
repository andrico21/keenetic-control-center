//! `kcc mcp stdio` stops on SIGTERM and SIGINT the way `kcc serve` does: it waits for a
//! management change still closing the router's safety bracket, writes its audit
//! entries and exits 0.
#![cfg(unix)]
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[path = "serve_bracket/proxy.rs"]
mod proxy;
#[expect(
    dead_code,
    reason = "a stdio session binds no port; only the stderr reader is shared"
)]
#[path = "support/serve_port.rs"]
mod serve_port;
#[expect(
    dead_code,
    reason = "this suite stops the session with SIGTERM and SIGINT only"
)]
#[path = "support/signal.rs"]
mod signal;
#[path = "support/spawning.rs"]
mod spawning;
#[expect(
    dead_code,
    reason = "the shared account password; this suite signs nobody in"
)]
#[path = "serve_bracket/support.rs"]
mod support;

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;
use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Child, ChildStdin, Stdio},
    sync::mpsc,
};

use kcc_app::{audit::verify_chain, secrets::MASTER_KEY_FILE_ENV};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{sync::Notify, task::block_in_place, time::timeout};
use wait_timeout::ChildExt as _;

use crate::{proxy::Action, serve_port::stderr_lines, signal::Signal, support::TestResult};

/// Upper bound for every wait on the child process.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(60);

/// The router-mode disarm line.
const DISARM: &str = "no system configuration fail-safe timer";

/// A running `kcc mcp stdio`; killed on drop if it is still running.
struct StdioServer {
    /// The process.
    child: Child,
    /// Its stdin, held open so that only the signal can end the session.
    stdin: ChildStdin,
    /// Its stderr lines.
    stderr: mpsc::Receiver<String>,
}

impl Drop for StdioServer {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

impl StdioServer {
    /// Starts `kcc mcp stdio` as `admin` for the router at `url`, state under `home`.
    fn start(home: &Path, url: &str) -> TestResult<Self> {
        let password_file =
            kcc_testkit::write_secret_file(home, "router.password", DEFAULT_PASSWORD)?;
        let key = home.join("master.key");
        master_key::write(&key, [17_u8; 32])?;
        let config = home.join("kcc.toml");
        fs::write(
            &config,
            format!(
                "[mcp]\nstdio_enabled = true\nstdio_role = \"admin\"\nallow_destructive = true\ntoolsets = [\"core\", \"raw\"]\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {:?}\n\n[[routers]]\nname = \"router\"\nurl = \"{url}\"\nlogin = \"admin\"\npassword_file = {:?}\n",
                home.join("state").display().to_string(),
                password_file.display().to_string()
            ),
        )?;
        let mut child = spawning::spawn(
            spawning::command(env!("CARGO_BIN_EXE_kcc"))
                .args(["mcp", "stdio", "--config", config.to_str().ok_or("path")?])
                .env("HOME", home)
                .env("XDG_CONFIG_HOME", home.join("config"))
                .env("XDG_STATE_HOME", home.join("state-home"))
                .env(MASTER_KEY_FILE_ENV, &key)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped()),
        )?;
        let stdin = child.stdin.take().ok_or("child stdin")?;
        let lines = stderr_lines(&mut child)?;
        Ok(Self {
            child,
            stdin,
            stderr: lines,
        })
    }

    /// Writes one JSON-RPC message.
    fn send(&mut self, message: &Value) -> TestResult {
        writeln!(self.stdin, "{message}")?;
        Ok(self.stdin.flush()?)
    }

    /// Sends `signal` to the process.
    fn signal(&self, which: Signal) -> TestResult {
        Ok(signal::send(&self.child, which)?)
    }

    /// Waits until a stderr line contains `needle`; fails once the process closed stderr.
    fn wait_line(&self, needle: &str) -> TestResult {
        while !self.stderr.recv_timeout(PROCESS_TIMEOUT)?.contains(needle) {}
        Ok(())
    }
}

/// Starts a management change over stdio whose disarm the relay holds back, sends
/// `signal` once the process has taken it, then releases the disarm.
async fn signalled_during_a_bracket(signal: Signal) -> TestResult {
    let (reached, released) = (Arc::new(Notify::new()), Arc::new(Notify::new()));
    let (at_disarm, gate) = (Arc::clone(&reached), Arc::clone(&released));
    let hold: Action = Box::new(move || {
        Box::pin(async move {
            at_disarm.notify_one();
            gate.notified().await;
        })
    });
    let directory = TempDir::new()?;
    let (router_address, router) = FakeRouter::spawn().await?;
    let relay = proxy::spawn(router_address, vec![(DISARM.as_bytes(), hold)]).await?;
    let mut stdio = StdioServer::start(directory.path(), &format!("http://{relay}"))?;
    stdio.send(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"signal","version":"1"}}}))?;
    stdio.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
    stdio.send(&json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/call","params":{"name":"kcc_cli_parse","arguments":{"host":"router","line":"no interface Bridge0","confirm":true}}}))?;
    timeout(PROCESS_TIMEOUT, reached.notified()).await?;

    stdio.signal(signal)?;
    if let Err(error) = block_in_place(|| stdio.wait_line("shutdown signal received")) {
        let ended = block_in_place(|| stdio.child.wait_timeout(PROCESS_TIMEOUT))?;
        return Err(format!(
            "no shutdown after SIGINT/SIGTERM ({error}); the process ended: {ended:?}"
        )
        .into());
    }
    released.notify_one();
    let status = block_in_place(|| stdio.child.wait_timeout(PROCESS_TIMEOUT))?
        .ok_or("kcc mcp stdio did not exit")?;

    assert_eq!(status.code(), Some(0_i32), "the exit code of `kcc serve`");
    assert!(
        router
            .request_log()
            .iter()
            .any(|record| record.command() == Some(DISARM)),
        "the disarm reached the router"
    );
    assert!(!router.recovery_armed(), "the router's timer is off");
    let fail_safe = verify_chain(&directory.path().join("state"))?
        .into_iter()
        .filter(|entry| {
            entry.action == "router.change_cli"
                && entry.target.as_deref() == Some("system configuration fail-safe timer")
        })
        .count();
    assert_eq!(
        fail_safe, 2,
        "the arm and, written after the signal, the disarm are in the audit log"
    );
    Ok(())
}

/// F-05: SIGTERM no longer kills `kcc mcp stdio` in the middle of a safety bracket; it
/// waits for the disarm, flushes the audit log and exits 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_waits_for_an_open_bracket() -> TestResult {
    signalled_during_a_bracket(Signal::Terminate).await
}

/// F-05: SIGINT (Ctrl-C) behaves like SIGTERM.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigint_waits_for_an_open_bracket() -> TestResult {
    signalled_during_a_bracket(Signal::Interrupt).await
}
