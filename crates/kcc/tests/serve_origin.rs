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

#[path = "support/master_key.rs"]
mod master_key;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;

use core::{error::Error, time::Duration};
use std::{
    fs,
    path::PathBuf,
    process::{Child, Stdio},
    sync::{Arc, mpsc},
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use reqwest::{Client, StatusCode, header};
use secrecy::SecretString;
use serve_port::{Start, await_ready, start_on_free_ports, stderr_lines};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);
const USERNAME: &str = "origin-user";
const PASSWORD: &str = "origin-password-123";
/// Where the configuration template takes the listen port.
const PORT_HOLE: &str = "{listen_port}";

/// A listening `kcc serve`, killed on drop.
struct Process {
    child: Child,
    /// Its stderr lines, kept open so that its logging never fails.
    _lines: mpsc::Receiver<String>,
    /// The listener's base URL.
    base_url: String,
}

impl Drop for Process {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

struct Fixture {
    _directory: TempDir,
    config: PathBuf,
    /// `kcc.toml` with [`PORT_HOLE`] for the listen port.
    template: String,
    home: PathBuf,
    key_path: PathBuf,
}

impl Fixture {
    fn new(extra_origin: Option<&str>) -> Result<Self, Box<dyn Error>> {
        Self::with_sections(extra_origin, "", "")
    }

    fn with_sections(
        extra_origin: Option<&str>,
        server_extra: &str,
        web_extra: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let state_dir = directory.path().join("state");
        let state = StateStore::open(&state_dir)?;
        let accounts = AccountStore::new(
            state,
            MasterKey::from_bytes([31_u8; 32]),
            Duration::from_mins(15),
            Arc::new(SystemClock::default()),
        );
        accounts.create(
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            NewAccount::new(
                USERNAME.to_owned(),
                SecretString::from(PASSWORD),
                "admin".to_owned(),
            ),
        )?;
        let key_path = directory.path().join("master.key");
        master_key::write(&key_path, [31_u8; 32])?;
        let configured_origins = extra_origin.map_or_else(String::new, |origin| {
            format!("allowed_origins = [\"{origin}\"]\n")
        });
        let template = format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {PORT_HOLE}\n{configured_origins}{server_extra}\n[web]\nenabled = true\n{web_extra}\n[mcp]\nhttp_enabled = false\n\n[state]\ndir = {:?}\n",
            state_dir.display().to_string()
        );
        Ok(Self {
            home: directory.path().to_owned(),
            config: directory.path().join("kcc.toml"),
            _directory: directory,
            template,
            key_path,
        })
    }

    /// Starts `kcc serve` on a free port and waits until it listens.
    fn serve(&self) -> Result<Process, Box<dyn Error>> {
        let (_ports, process) = start_on_free_ports(|[port]| {
            fs::write(
                &self.config,
                self.template.replace(PORT_HOLE, &port.to_string()),
            )?;
            let mut child = spawning::spawn(
                spawning::command(env!("CARGO_BIN_EXE_kcc"))
                    .args(["serve", "--config"])
                    .arg(&self.config)
                    .env("HOME", &self.home)
                    .env("XDG_CONFIG_HOME", self.home.join("config"))
                    .env("XDG_STATE_HOME", self.home.join("state-home"))
                    .env(MASTER_KEY_FILE_ENV, &self.key_path)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped()),
            )?;
            let lines = stderr_lines(&mut child)?;
            let started = await_ready(&lines, |line| line.contains("listening"), PROCESS_TIMEOUT)?;
            let process = Process {
                child,
                _lines: lines,
                base_url: format!("http://127.0.0.1:{port}"),
            };
            Ok::<_, Box<dyn Error>>(match started {
                Start::Ready(_seen) => Start::Ready(process),
                Start::AddressInUse => Start::AddressInUse,
            })
        })?;
        Ok(process)
    }
}

#[tokio::test]
async fn same_origin_login_post_is_accepted_without_configured_origins() -> TestResult {
    let fixture = Fixture::new(None)?;
    let process = fixture.serve()?;
    let client = client()?;
    let login_page = client
        .get(format!("{}/ui/login", process.base_url))
        .send()
        .await?;
    let cookie = cookie_pair(&login_page)?;
    let csrf = meta_content(&login_page.text().await?, "csrf-token").ok_or("missing CSRF")?;

    let response = client
        .post(format!("{}/ui/login", process.base_url))
        .header(header::COOKIE, cookie)
        .header(header::ORIGIN, &process.base_url)
        .header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!("username={USERNAME}&password={PASSWORD}"))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    Ok(())
}

/// `SEC1-03` / `F-03`: behind an HTTPS reverse proxy the listener is plain HTTP, yet the
/// session cookie is `Secure` with the `__Host-` prefix and the CSP is the TLS one.
#[tokio::test]
async fn https_public_url_gives_a_secure_host_cookie_and_the_tls_csp() -> TestResult {
    let fixture = Fixture::with_sections(
        None,
        "trusted_proxies = [\"127.0.0.1/32\"]\n",
        "public_url = \"https://kcc.example.net/\"\n",
    )?;
    let process = fixture.serve()?;

    let login_page = client()?
        .get(format!("{}/ui/login", process.base_url))
        .send()
        .await?;

    let set_cookie = header_text(&login_page, &header::SET_COOKIE)?;
    assert!(
        set_cookie.starts_with("__Host-kcc_session="),
        "{set_cookie}"
    );
    assert!(set_cookie.contains("Secure"), "{set_cookie}");
    assert!(
        header_text(&login_page, &header::CONTENT_SECURITY_POLICY)?
            .contains("upgrade-insecure-requests")
    );
    Ok(())
}

/// Plain HTTP on loopback with no public URL keeps the plain cookie and the plain CSP.
#[tokio::test]
async fn plain_loopback_keeps_the_plain_cookie_and_csp() -> TestResult {
    let fixture = Fixture::new(None)?;
    let process = fixture.serve()?;

    let login_page = client()?
        .get(format!("{}/ui/login", process.base_url))
        .send()
        .await?;

    let set_cookie = header_text(&login_page, &header::SET_COOKIE)?;
    assert!(set_cookie.starts_with("kcc_session="), "{set_cookie}");
    assert!(!set_cookie.contains("Secure"), "{set_cookie}");
    assert!(
        !header_text(&login_page, &header::CONTENT_SECURITY_POLICY)?
            .contains("upgrade-insecure-requests")
    );
    Ok(())
}

#[tokio::test]
async fn foreign_origin_is_refused_by_shared_listener() -> TestResult {
    let fixture = Fixture::new(None)?;
    let process = fixture.serve()?;

    let response = client()?
        .get(format!("{}/healthz", process.base_url))
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
    let process = fixture.serve()?;

    let response = client()?
        .get(format!("{}/healthz", process.base_url))
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

fn header_text(
    response: &reqwest::Response,
    name: &header::HeaderName,
) -> Result<String, Box<dyn Error>> {
    Ok(response
        .headers()
        .get(name)
        .ok_or_else(|| std::io::Error::other(format!("missing {name}")))?
        .to_str()?
        .to_owned())
}

fn meta_content(html: &str, name: &str) -> Option<String> {
    let marker = format!("<meta name=\"{name}\" content=\"");
    html.split_once(&marker)
        .and_then(|(_, tail)| tail.split_once('\"'))
        .map(|(value, _)| value.to_owned())
}
