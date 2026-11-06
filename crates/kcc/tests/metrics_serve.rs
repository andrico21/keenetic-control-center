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

use core::{error::Error, time::Duration};
use std::{
    collections::BTreeSet,
    env, fs,
    io::{BufRead as _, BufReader},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
};

use kcc_app::secrets::MASTER_KEY_FILE_ENV;
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
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
    /// Starts `kcc serve --config <config>` with a hermetic home and master key.
    fn spawn(config: &Path, home: &Path, key: &Path) -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kcc"))
            .args([
                "serve",
                "--config",
                config.to_str().ok_or("non-UTF-8 path")?,
            ])
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("state-home"))
            .env(MASTER_KEY_FILE_ENV, key)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("child stderr unavailable")?;
        let (sender, lines) = mpsc::channel();
        drop(thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        }));
        Ok(Self { child, lines })
    }

    /// Waits until every needle has appeared in a stderr line.
    fn wait_for(&self, needles: &[&str]) -> Result<(), Box<dyn Error>> {
        let deadline = std::time::Instant::now()
            .checked_add(PROCESS_TIMEOUT)
            .ok_or("deadline overflow")?;
        let mut pending: BTreeSet<&str> = needles.iter().copied().collect();
        let mut seen = String::new();
        while !pending.is_empty() {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let line = self
                .lines
                .recv_timeout(remaining)
                .map_err(|error| format!("{error}; waiting for {pending:?}; stderr:\n{seen}"))?;
            pending.retain(|needle| !line.contains(needle));
            seen.push_str(&line);
            seen.push('\n');
        }
        Ok(())
    }
}

/// An unused loopback port at or above 1024.
fn reserve_port() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

/// Writes a 0600 master key.
fn write_master_key(path: &Path) -> TestResult {
    fs::write(path, [17_u8; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
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
    let output = Command::new(binary)
        .args(["check", "metrics"])
        .stdin(fs::File::open(&scrape)?)
        .output()?;
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
    let password_file = directory.path().join("router.password");
    fs::write(&password_file, DEFAULT_PASSWORD)?;
    let key = directory.path().join("master.key");
    write_master_key(&key)?;
    let (port, metrics_port) = (reserve_port()?, reserve_port()?);
    let config = directory.path().join("kcc.toml");
    fs::write(
        &config,
        format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n\n[metrics]\nenabled = true\nbind = \"127.0.0.1:{metrics_port}\"\ninterval = \"15s\"\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {:?}\n\n[[routers]]\nname = \"fake\"\nurl = \"http://{router_address}\"\nlogin = \"admin\"\npassword_file = {:?}\n",
            directory.path().join("state").display().to_string(),
            password_file.display().to_string()
        ),
    )?;
    let server = Server::spawn(&config, directory.path(), &key)?;
    server.wait_for(&["metrics endpoint listening", "router metrics available"])?;
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
