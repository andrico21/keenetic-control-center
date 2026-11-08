//! The exporter while `kcc serve` runs: routers added and removed at runtime, the
//! firmware-update family, and the Web session gauge.

use core::{error::Error, net::SocketAddr, time::Duration};
use std::{fs, path::Path, process::Command, sync::Arc, time::Instant};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    persist::StateStore,
    registry::{ManagedRouterProfile, RoutersDocument},
    secrets::MasterKey,
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, Handle, firmware_update::FirmwareUpdate, model::Profile,
};
use reqwest::{Client, StatusCode, header, redirect::Policy};
use secrecy::SecretString;
use tempfile::TempDir;
use url::Url;

use super::{PROCESS_TIMEOUT, Server, TestResult, reserve_port, write_master_key};

/// One `kcc serve` with metrics and the Web UI over the fake router `fake`.
struct Running {
    /// State, configuration and password file.
    directory: TempDir,
    /// The server.
    server: Server,
    /// The fake router.
    router: Handle,
    /// The Web UI base URL.
    base: String,
    /// The metrics listener's scrape URL.
    metrics: String,
}

/// Starts the server over a fake router that answers `update`, with the administrator
/// `alice`, and waits until the router's metrics are available.
async fn start(update: Option<FirmwareUpdate>) -> Result<Running, Box<dyn Error>> {
    let directory = TempDir::new()?;
    let mut fake = FakeRouter::builder(Profile::default()).build()?;
    if let Some(answer) = update {
        fake = fake.with_firmware_update(answer);
    }
    let (address, router) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let password_file = directory.path().join("router.password");
    fs::write(&password_file, DEFAULT_PASSWORD)?;
    let state = StateStore::open(&directory.path().join("state"))?;
    AccountStore::new(
        state,
        MasterKey::from_bytes([17_u8; 32]),
        Duration::from_mins(15),
        Arc::new(SystemClock::default()),
    )
    .create(NewAccount::new(
        "alice".to_owned(),
        SecretString::from("correct horse battery staple"),
        "admin".to_owned(),
    ))?;
    let key = directory.path().join("master.key");
    write_master_key(&key)?;
    let (port, metrics_port) = (reserve_port()?, reserve_port()?);
    let config = directory.path().join("kcc.toml");
    fs::write(
        &config,
        format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n\n[web]\nenabled = true\n\n[metrics]\nenabled = true\nbind = \"127.0.0.1:{metrics_port}\"\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {:?}\n\n[[routers]]\nname = \"fake\"\nurl = \"http://{address}\"\nlogin = \"admin\"\npassword_file = {:?}\n",
            directory.path().join("state").display().to_string(),
            password_file.display().to_string()
        ),
    )?;
    let server = Server::spawn(&config, directory.path(), &key)?;
    server.wait_for(&["metrics endpoint listening", "router metrics available"])?;
    Ok(Running {
        directory,
        server,
        router,
        base: format!("http://127.0.0.1:{port}"),
        metrics: format!("http://127.0.0.1:{metrics_port}/metrics"),
    })
}

/// An HTTP client that does not follow redirects.
fn client() -> Result<Client, Box<dyn Error>> {
    let _installed = rustls::crypto::ring::default_provider().install_default();
    Ok(Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?)
}

/// The scrape text at `url`.
async fn scrape(http: &Client, url: &str) -> Result<String, Box<dyn Error>> {
    Ok(http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

impl Running {
    /// Waits until one stderr line contains every needle.
    fn wait_for_line(&self, needles: &[&str]) -> TestResult {
        let deadline = Instant::now()
            .checked_add(PROCESS_TIMEOUT)
            .ok_or("deadline overflow")?;
        loop {
            let line = self
                .server
                .lines
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|error| format!("{error} while waiting for {needles:?}"))?;
            if needles.iter().all(|needle| line.contains(needle)) {
                return Ok(());
            }
        }
    }

    /// Sends SIGHUP to the server.
    fn hangup(&self) -> TestResult {
        let status = Command::new("kill")
            .args(["-HUP", &self.server.child.id().to_string()])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err("kill -HUP failed".into())
        }
    }

    /// Replaces the state-defined routers with `routers`, as `kcc router add|remove` do.
    fn set_routers(&self, routers: Vec<ManagedRouterProfile>) -> TestResult {
        StateStore::open(&self.directory.path().join("state"))?
            .update(|document: &mut RoutersDocument| document.routers = routers)?;
        Ok(())
    }
}

/// Signs `alice` in to the Web UI at `base`.
async fn sign_in(http: &Client, base: &str) -> TestResult {
    let login = http.get(format!("{base}/ui/login")).send().await?;
    let cookie = login
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::to_owned)
        .ok_or("no cookie")?;
    let html = login.text().await?;
    let csrf = html
        .split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
        .ok_or("no CSRF token")?;
    let response = http
        .post(format!("{base}/ui/login"))
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, base)
        .header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body("username=alice&password=correct+horse+battery+staple")
        .send()
        .await?;
    if response.status() == StatusCode::SEE_OTHER {
        Ok(())
    } else {
        Err(format!("sign-in answered {}", response.status()).into())
    }
}

/// The profile `id` of the router at `address`, with its password in `password`.
fn profile(
    id: &str,
    address: SocketAddr,
    password: &Path,
) -> Result<ManagedRouterProfile, Box<dyn Error>> {
    Ok(ManagedRouterProfile::new(
        id.to_owned(),
        Url::parse(&format!("http://{address}"))?,
        "admin".to_owned(),
        password.to_owned(),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routers_added_and_removed_at_runtime_are_scraped_and_dropped() -> TestResult {
    let running = start(None).await?;
    let http = client()?;
    let (address, second) = FakeRouter::spawn().await?;
    let password = running.directory.path().join("router.password");
    running.set_routers(vec![profile("second", address, &password)?])?;
    running.hangup()?;
    running.wait_for_line(&["router metrics available", "second"])?;
    let added = scrape(&http, &running.metrics).await?;
    assert!(
        added.contains("keenetic_up{router=\"second\"} 1"),
        "the added router is scraped without a restart:\n{added}"
    );

    running.set_routers(Vec::new())?;
    running.hangup()?;
    running.wait_for_line(&["router metrics stopped", "second"])?;
    let removed = scrape(&http, &running.metrics).await?;
    assert!(
        !removed
            .lines()
            .any(|line| line.starts_with("keenetic_") && line.contains("router=\"second\"")),
        "the removed router's series are gone:\n{removed}"
    );
    assert!(
        removed.contains("keenetic_up{router=\"fake\"} 1"),
        "fake stays"
    );
    second.shutdown().await?;
    running.router.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_update_and_session_families_are_scraped() -> TestResult {
    let running = start(Some(FirmwareUpdate::Available("5.1.4".to_owned()))).await?;
    let http = client()?;
    running.wait_for_line(&["firmware update status exported", "fake"])?;
    let checked = scrape(&http, &running.metrics).await?;
    assert!(
        checked.contains("keenetic_firmware_update_available{router=\"fake\"} 1"),
        "the update family:\n{checked}"
    );
    assert!(
        checked.contains("kcc_web_sessions 0"),
        "nobody signed in yet"
    );

    sign_in(&http, &running.base).await?;
    // The gauge is sampled every 15 s: the sampling cadence is the behavior under test,
    // so the scrape is repeated until the next sample, bounded by the process timeout.
    let deadline = Instant::now()
        .checked_add(PROCESS_TIMEOUT)
        .ok_or("deadline overflow")?;
    loop {
        let text = scrape(&http, &running.metrics).await?;
        if text.contains("kcc_web_sessions 1") {
            break;
        }
        assert!(Instant::now() < deadline, "no session sample:\n{text}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    running.router.shutdown().await?;
    Ok(())
}
