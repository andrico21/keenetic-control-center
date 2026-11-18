//! `kcc serve` with `[metrics] enabled`: the kit `/metrics` listener renders router data.
#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process and own temporary OS resources"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[path = "support/serve_port.rs"]
mod serve_port;
#[expect(dead_code, reason = "the exporter tests only reload the configuration")]
#[path = "support/signal.rs"]
mod signal;
#[path = "support/spawning.rs"]
mod spawning;

use core::{error::Error, time::Duration};
use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
    process::{Child, Stdio},
    sync::mpsc,
};

use kcc_app::secrets::MASTER_KEY_FILE_ENV;
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use serve_port::{Start, await_ready, start_on_free_ports, stderr_lines};
use tempfile::TempDir;

/// Test result.
type TestResult = Result<(), Box<dyn Error>>;

/// Upper bound for every wait on the child process.
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);

/// Kills the child on drop.
struct Server {
    /// The `kcc serve` process.
    child: Child,
    /// Child stderr lines.
    lines: mpsc::Receiver<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

impl Server {
    /// Writes `<home>/kcc.toml` from `config` on two free ports (listener, metrics), starts
    /// `kcc serve` with a hermetic home and the master key `key`, and waits until both
    /// listeners serve and the router's metrics are available. Returns the ports.
    fn start<F>(home: &Path, key: &Path, config: F) -> Result<([u16; 2], Self), Box<dyn Error>>
    where
        F: Fn([u16; 2]) -> String,
    {
        let path = home.join("kcc.toml");
        start_on_free_ports(|ports| {
            fs::write(&path, config(ports))?;
            let mut child = spawning::spawn(
                spawning::command(env!("CARGO_BIN_EXE_kcc"))
                    .args(["serve", "--config", path.to_str().ok_or("non-UTF-8 path")?])
                    .env("HOME", home)
                    .env("XDG_CONFIG_HOME", home.join("config"))
                    .env("XDG_STATE_HOME", home.join("state-home"))
                    .env(MASTER_KEY_FILE_ENV, key)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped()),
            )?;
            let lines = stderr_lines(&mut child)?;
            let server = Self { child, lines };
            let mut pending: BTreeSet<&str> =
                ["metrics endpoint listening", "router metrics available"]
                    .into_iter()
                    .collect();
            let started = await_ready(
                &server.lines,
                |line| {
                    pending.retain(|needle| !line.contains(needle));
                    pending.is_empty()
                },
                PROCESS_TIMEOUT,
            )?;
            Ok::<_, Box<dyn Error>>(match started {
                Start::Ready(_seen) => Start::Ready(server),
                Start::AddressInUse => Start::AddressInUse,
            })
        })
    }
}

/// `promtool` from `KCC_PROMTOOL` or `PATH`.
fn promtool() -> Option<PathBuf> {
    env::var_os("KCC_PROMTOOL").map(PathBuf::from).or_else(|| {
        env::split_paths(&env::var_os("PATH")?)
            .map(|directory| directory.join("promtool"))
            .find(|candidate| candidate.is_file())
    })
}

/// Runs `promtool check metrics` on `text`; logs `promtool-skip` when it is unavailable.
fn promtool_check(text: &str, directory: &Path) -> TestResult {
    let Some(binary) = promtool() else {
        tracing::warn!("promtool-skip: set KCC_PROMTOOL or put promtool on PATH");
        return Ok(());
    };
    let scrape = directory.join("scrape.prom");
    fs::write(&scrape, text)?;
    let output = spawning::spawn(
        spawning::command(binary)
            .args(["check", "metrics"])
            .stdin(fs::File::open(&scrape)?)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )?
    .wait_with_output()?;
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success() && report.trim().is_empty(),
        "promtool:\n{report}"
    );
    Ok(())
}

/// The exporter serves router families from the shared poller's cache on the kit
/// listener, and the exposition passes promtool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_exposes_router_metrics_on_the_kit_listener() -> TestResult {
    drop(tracing_subscriber::fmt().with_test_writer().try_init());
    let directory = TempDir::new()?;
    let (router_address, router) = FakeRouter::spawn().await?;
    let password_file =
        kcc_testkit::write_secret_file(directory.path(), "router.password", DEFAULT_PASSWORD)?;
    let key = directory.path().join("master.key");
    master_key::write(&key, [17_u8; 32])?;
    let state_dir = directory.path().join("state").display().to_string();
    let password = password_file.display().to_string();
    let ([_port, metrics_port], server) = Server::start(
        directory.path(),
        &key,
        |[port, metrics_port]| {
            format!(
                "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n\n[metrics]\nenabled = true\nbind = \"127.0.0.1:{metrics_port}\"\ninterval = \"15s\"\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {state_dir:?}\n\n[[routers]]\nname = \"fake\"\nurl = \"http://{router_address}\"\nlogin = \"admin\"\npassword_file = {password:?}\n",
            )
        },
    )?;
    let _installed = rustls::crypto::ring::default_provider().install_default();
    let text = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?
        .get(format!("http://127.0.0.1:{metrics_port}/metrics"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    for expected in [
        "keenetic_up{router=\"fake\"} 1",
        "keenetic_config_unsaved{router=\"fake\"} 0",
        "kcc_build_info{version=\"",
        "kcc_router_requests_total{outcome=\"ok\",router=\"fake\"}",
    ] {
        assert!(text.contains(expected), "{expected} missing:\n{text}");
    }
    promtool_check(&text, directory.path())?;
    drop(server);
    router.shutdown().await?;
    Ok(())
}

#[path = "metrics_serve/runtime.rs"]
mod runtime;
