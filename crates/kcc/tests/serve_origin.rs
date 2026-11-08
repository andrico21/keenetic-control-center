//! Origin policy acceptance tests.
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
    fs,
    io::{BufRead as _, BufReader},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, mpsc},
    thread,
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use reqwest::{Client, StatusCode, header};
use secrecy::SecretString;
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
const USERNAME: &str = "origin-user";
const PASSWORD: &str = "origin-password-123";

struct Process {
    child: Child,
    stderr_rx: mpsc::Receiver<String>,
    stderr_thread: Option<thread::JoinHandle<()>>,
}

impl Process {
    fn wait_listening(&self) -> TestResult {
        loop {
            let line = self.stderr_rx.recv_timeout(PROCESS_TIMEOUT)?;
            if line.contains("listening") {
                return Ok(());
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            drop(self.child.kill());
            drop(self.child.wait());
        }
        if let Some(thread) = self.stderr_thread.take() {
            drop(thread.join());
        }
    }
}

struct Fixture {
    _directory: TempDir,
    config: PathBuf,
    home: PathBuf,
    key_path: PathBuf,
    base_url: String,
}

impl Fixture {
    fn new(extra_origin: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let state_dir = directory.path().join("state");
        let state = StateStore::open(&state_dir)?;
        let accounts = AccountStore::new(
            state,
            MasterKey::from_bytes([31_u8; 32]),
            Duration::from_mins(15),
            Arc::new(SystemClock::default()),
        );
        accounts.create(NewAccount::new(
            USERNAME.to_owned(),
            SecretString::from(PASSWORD),
            "admin".to_owned(),
        ))?;
        let key_path = directory.path().join("master.key");
        write_master_key(&key_path)?;
        let port = reserve_port()?;
        let configured_origins = extra_origin.map_or_else(String::new, |origin| {
            format!("allowed_origins = [\"{origin}\"]\n")
        });
        let config = directory.path().join("kcc.toml");
        fs::write(
            &config,
            format!(
                "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n{configured_origins}\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = false\n\n[state]\ndir = {:?}\n",
                state_dir.display().to_string()
            ),
        )?;
        Ok(Self {
            home: directory.path().to_owned(),
            _directory: directory,
            config,
            key_path,
            base_url: format!("http://127.0.0.1:{port}"),
        })
    }

    fn spawn(&self) -> Result<Process, Box<dyn Error>> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kcc"))
            .args(["serve", "--config"])
            .arg(&self.config)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join("config"))
            .env("XDG_STATE_HOME", self.home.join("state-home"))
            .env(MASTER_KEY_FILE_ENV, &self.key_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().ok_or("child stderr unavailable")?;
        let (stderr_tx, stderr_rx) = mpsc::channel();
        let stderr_thread = thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if stderr_tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Process {
            child,
            stderr_rx,
            stderr_thread: Some(stderr_thread),
        })
    }
}

#[tokio::test]
async fn same_origin_login_post_is_accepted_without_configured_origins() -> TestResult {
    let fixture = Fixture::new(None)?;
    let process = fixture.spawn()?;
    process.wait_listening()?;
    let client = client()?;
    let login_page = client
        .get(format!("{}/ui/login", fixture.base_url))
        .send()
        .await?;
    let cookie = cookie_pair(&login_page)?;
    let csrf = meta_content(&login_page.text().await?, "csrf-token").ok_or("missing CSRF")?;

    let response = client
        .post(format!("{}/ui/login", fixture.base_url))
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, &fixture.base_url)
        .header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("username={USERNAME}&password={PASSWORD}"))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    Ok(())
}

#[tokio::test]
async fn foreign_origin_is_refused_by_shared_listener() -> TestResult {
    let fixture = Fixture::new(None)?;
    let process = fixture.spawn()?;
    process.wait_listening()?;

    let response = client()?
        .get(format!("{}/healthz", fixture.base_url))
        .header(header::ORIGIN, "http://evil.example")
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn configured_extra_origin_is_preserved_with_derived_origins() -> TestResult {
    let extra_origin = "https://proxy.example";
    let fixture = Fixture::new(Some(extra_origin))?;
    let process = fixture.spawn()?;
    process.wait_listening()?;

    let response = client()?
        .get(format!("{}/healthz", fixture.base_url))
        .header(header::ORIGIN, extra_origin)
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

fn client() -> Result<Client, Box<dyn Error>> {
    let _installed = rustls::crypto::ring::default_provider().install_default();
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?)
}

fn reserve_port() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn write_master_key(path: &Path) -> TestResult {
    fs::write(path, [31_u8; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn cookie_pair(response: &reqwest::Response) -> Result<String, Box<dyn Error>> {
    response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| std::io::Error::other("missing Set-Cookie"))?
        .to_str()?
        .split(';')
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "empty Set-Cookie".into())
}

fn meta_content(html: &str, name: &str) -> Option<String> {
    let marker = format!("<meta name=\"{name}\" content=\"");
    html.split_once(&marker)
        .and_then(|(_, tail)| tail.split_once('\"'))
        .map(|(value, _)| value.to_owned())
}
