//! Process-level HTTP and stdio server acceptance tests.
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
    io::{BufRead as _, BufReader, Write as _},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{Arc, mpsc},
    thread,
};

use kcc_app::{
    accounts::{AccountStore, NewAccount, SystemClock},
    api_keys::{create_api_key, expose_created_key},
    persist::StateStore,
    secrets::{MASTER_KEY_FILE_ENV, MasterKey},
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use reqwest::{Client, StatusCode, header};
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;
use wait_timeout::ChildExt as _;

type TestResult = Result<(), Box<dyn Error>>;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);

struct ChildGuard {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout_rx: mpsc::Receiver<String>,
    stdout_thread: Option<thread::JoinHandle<()>>,
    stderr_rx: mpsc::Receiver<String>,
    stderr_thread: Option<thread::JoinHandle<()>>,
    stderr: String,
}

impl ChildGuard {
    fn spawn(arguments: &[&str], home: &Path, key_path: &Path) -> Result<Self, Box<dyn Error>> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_kcc"))
            .args(arguments)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_STATE_HOME", home.join("state-home"))
            .env(MASTER_KEY_FILE_ENV, key_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdin = child.stdin.take().ok_or("child stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("child stdout unavailable")?;
        let stderr = child.stderr.take().ok_or("child stderr unavailable")?;
        let (stdout_tx, stdout_rx) = mpsc::channel();
        let stdout_thread = thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if stdout_tx.send(line).is_err() {
                    break;
                }
            }
        });
        let (stderr_tx, stderr_rx) = mpsc::channel();
        let stderr_thread = thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if stderr_tx.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin: Some(stdin),
            stdout_rx,
            stdout_thread: Some(stdout_thread),
            stderr_rx,
            stderr_thread: Some(stderr_thread),
            stderr: String::new(),
        })
    }

    fn wait_listening(&mut self) -> TestResult {
        let deadline = std::time::Instant::now()
            .checked_add(PROCESS_TIMEOUT)
            .ok_or("process deadline overflow")?;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let line = self.stderr_rx.recv_timeout(remaining)?;
            self.stderr.push_str(&line);
            self.stderr.push('\n');
            if line.contains("listening") {
                return Ok(());
            }
        }
    }

    fn write_line(&mut self, value: &Value) -> TestResult {
        let stdin = self.stdin.as_mut().ok_or("child stdin is closed")?;
        serde_json::to_writer(&mut *stdin, value)?;
        stdin.write_all(b"\n")?;
        stdin.flush()?;
        Ok(())
    }

    fn read_stdout_line(&self) -> Result<String, Box<dyn Error>> {
        Ok(self.stdout_rx.recv_timeout(PROCESS_TIMEOUT)?)
    }

    fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }

    fn wait(mut self) -> Result<(ExitStatus, String), Box<dyn Error>> {
        let status = self
            .child
            .wait_timeout(PROCESS_TIMEOUT)?
            .ok_or("child did not exit before deadline")?;
        if let Some(stdout_thread) = self.stdout_thread.take() {
            stdout_thread
                .join()
                .map_err(|_panic| "stdout reader panicked")?;
        }
        if let Some(stderr_thread) = self.stderr_thread.take() {
            stderr_thread
                .join()
                .map_err(|_panic| "stderr reader panicked")?;
        }
        while let Ok(line) = self.stderr_rx.try_recv() {
            self.stderr.push_str(&line);
            self.stderr.push('\n');
        }
        Ok((status, self.stderr.clone()))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            drop(self.child.kill());
            drop(self.child.wait());
        }
        if let Some(stderr_thread) = self.stderr_thread.take() {
            drop(stderr_thread.join());
        }
        if let Some(stdout_thread) = self.stdout_thread.take() {
            drop(stdout_thread.join());
        }
    }
}

struct Fixture {
    _directory: TempDir,
    config: PathBuf,
    home: PathBuf,
    key_path: PathBuf,
    base_url: String,
    viewer_key: String,
    operator_key: String,
    router: kcc_testkit::Handle,
}

impl Fixture {
    async fn new(http_enabled: bool) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let (router_address, router) = FakeRouter::spawn().await?;
        let password_file = directory.path().join("router.password");
        fs::write(&password_file, DEFAULT_PASSWORD)?;
        let state_dir = directory.path().join("state");
        let state = StateStore::open(&state_dir)?;
        let key = MasterKey::from_bytes([17_u8; 32]);
        let accounts = AccountStore::new(
            state.clone(),
            key,
            Duration::from_mins(15),
            Arc::new(SystemClock::default()),
        );
        accounts.create(NewAccount::new(
            "viewer".to_owned(),
            SecretString::from("viewer-password-123".to_owned()),
            "viewer".to_owned(),
        ))?;
        let viewer = create_api_key(&state, "viewer-key".to_owned(), "viewer".to_owned(), 1)?;
        let viewer_key = expose_created_key(&viewer).to_owned();
        let operator = create_api_key(&state, "operator-key".to_owned(), "operator".to_owned(), 2)?;
        let operator_key = expose_created_key(&operator).to_owned();
        let key_path = directory.path().join("master.key");
        write_master_key(&key_path)?;
        let port = reserve_port()?;
        let config = directory.path().join("kcc.toml");
        fs::write(
            &config,
            format!(
                "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n\n[web]\nenabled = true\n\n[mcp]\nhttp_enabled = {http_enabled}\nstdio_enabled = true\n\n[outbound]\nallow_loopback = true\n\n[state]\ndir = {:?}\n\n[[routers]]\nname = \"router\"\nurl = \"http://{router_address}\"\nlogin = \"admin\"\npassword_file = {:?}\n",
                state_dir.display().to_string(),
                password_file.display().to_string()
            ),
        )?;
        Ok(Self {
            _directory: directory,
            config,
            home: state_dir
                .parent()
                .ok_or("state directory has no parent")?
                .to_owned(),
            key_path,
            base_url: format!("http://127.0.0.1:{port}"),
            viewer_key,
            operator_key,
            router,
        })
    }

    fn spawn(&self) -> Result<ChildGuard, Box<dyn Error>> {
        self.spawn_command(&["serve"])
    }

    fn spawn_command(&self, command: &[&str]) -> Result<ChildGuard, Box<dyn Error>> {
        let mut arguments = command.to_vec();
        arguments.extend([
            "--config",
            self.config.to_str().ok_or("non-UTF-8 config path")?,
        ]);
        ChildGuard::spawn(&arguments, &self.home, &self.key_path)
    }

    async fn shutdown(self) -> TestResult {
        self.router.shutdown().await?;
        Ok(())
    }
}

fn reserve_port() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn write_master_key(path: &Path) -> TestResult {
    fs::write(path, [17_u8; 32])?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn client() -> Result<Client, Box<dyn Error>> {
    let _installed = rustls::crypto::ring::default_provider().install_default();
    Ok(Client::builder().timeout(Duration::from_secs(5)).build()?)
}

async fn initialize(client: &Client, url: &str, api_key: &str) -> Result<String, Box<dyn Error>> {
    let response = client
        .post(format!("{url}/mcp"))
        .bearer_auth(api_key)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}))
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("initialize returned {}", response.status()).into());
    }
    response
        .headers()
        .get("mcp-session-id")
        .ok_or("initialize omitted MCP session id")?
        .to_str()
        .map(str::to_owned)
        .map_err(Into::into)
}

async fn initialized(
    client: &Client,
    url: &str,
    api_key: &str,
    session: &str,
) -> Result<(), Box<dyn Error>> {
    let response = client
        .post(format!("{url}/mcp"))
        .bearer_auth(api_key)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Mcp-Session-Id", session)
        .json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("initialized notification returned {}", response.status()).into())
    }
}

async fn tools_list(
    client: &Client,
    url: &str,
    api_key: &str,
    session: &str,
) -> Result<Value, Box<dyn Error>> {
    let response = client
        .post(format!("{url}/mcp"))
        .bearer_auth(api_key)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("Mcp-Session-Id", session)
        .json(&json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/list","params":{}}))
        .send()
        .await?
        .error_for_status()?;
    let body = response.text().await?;
    let json_text = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim_start)
        .find(|payload| !payload.is_empty())
        .unwrap_or(body.as_str());
    Ok(serde_json::from_str(json_text)?)
}

fn tool_names(tools: &[Value]) -> impl Iterator<Item = &str> {
    tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str))
}

#[tokio::test]
async fn serve_exposes_health_web_and_viewer_filtered_mcp() -> TestResult {
    let fixture = Fixture::new(true).await?;
    let mut process = fixture.spawn()?;
    process.wait_listening()?;
    let client = client()?;

    assert_eq!(
        client
            .get(format!("{}/healthz", fixture.base_url))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(format!("{}/readyz", fixture.base_url))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    let login = client
        .get(format!("{}/ui/login", fixture.base_url))
        .send()
        .await?;
    assert_eq!(login.status(), StatusCode::OK);
    assert_eq!(
        login
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok()),
        Some(kcc_web::csp::policy(false).as_str())
    );
    let unauthorized = client
        .post(format!("{}/mcp", fixture.base_url))
        .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"tools/list","params":{}}))
        .send()
        .await?;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let viewer_session = initialize(&client, &fixture.base_url, &fixture.viewer_key).await?;
    initialized(
        &client,
        &fixture.base_url,
        &fixture.viewer_key,
        &viewer_session,
    )
    .await?;
    let viewer_list = tools_list(
        &client,
        &fixture.base_url,
        &fixture.viewer_key,
        &viewer_session,
    )
    .await?;
    let viewer_tools = viewer_list
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("tools/list omitted tools")?;
    assert!(!viewer_tools.is_empty(), "viewer sees read tools");
    assert!(!tool_names(viewer_tools).any(|name| name == "kcc_config_save"));
    assert!(viewer_tools.iter().all(|tool| {
        tool.pointer("/annotations/readOnlyHint")
            .and_then(Value::as_bool)
            == Some(true)
    }));
    let operator_session = initialize(&client, &fixture.base_url, &fixture.operator_key).await?;
    initialized(
        &client,
        &fixture.base_url,
        &fixture.operator_key,
        &operator_session,
    )
    .await?;
    let operator_list = tools_list(
        &client,
        &fixture.base_url,
        &fixture.operator_key,
        &operator_session,
    )
    .await?;
    let operator_tools = operator_list
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("operator tools/list omitted tools")?;
    assert!(tool_names(operator_tools).any(|name| name == "kcc_config_save"));

    drop(process);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn disabled_http_mcp_still_serves_web_without_tools() -> TestResult {
    let fixture = Fixture::new(false).await?;
    let mut process = fixture.spawn()?;
    process.wait_listening()?;
    let client = client()?;

    assert_eq!(
        client
            .get(format!("{}/ui/login", fixture.base_url))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    let session = initialize(&client, &fixture.base_url, &fixture.viewer_key).await?;
    initialized(&client, &fixture.base_url, &fixture.viewer_key, &session).await?;
    let listed = tools_list(&client, &fixture.base_url, &fixture.viewer_key, &session).await?;
    assert!(
        listed
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty),
        "HTTP-disabled MCP registers zero tools"
    );

    drop(process);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn second_serve_fails_fast_while_first_stays_healthy() -> TestResult {
    let fixture = Fixture::new(true).await?;
    let mut first = fixture.spawn()?;
    first.wait_listening()?;
    let second = fixture.spawn()?;

    let (status, stderr) = second.wait()?;

    assert_eq!(status.code(), Some(1_i32));
    assert!(
        stderr.contains("another kcc serve holds the server lock"),
        "{stderr}"
    );
    assert!(
        stderr.contains(&fixture.home.display().to_string()),
        "{stderr}"
    );
    assert_eq!(
        client()?
            .get(format!("{}/healthz", fixture.base_url))
            .send()
            .await?
            .status(),
        StatusCode::OK
    );
    drop(first);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn enabled_stdio_runs_beside_serve_as_viewer() -> TestResult {
    let fixture = Fixture::new(true).await?;
    let mut server = fixture.spawn()?;
    server.wait_listening()?;
    let mut stdio = fixture.spawn_command(&["mcp", "stdio"])?;

    stdio.write_line(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}))?;
    let initialized_response: Value = serde_json::from_str(&stdio.read_stdout_line()?)?;
    assert_eq!(initialized_response.get("id"), Some(&Value::from(1_u32)));
    stdio.write_line(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
    stdio.write_line(&json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/list","params":{}}))?;
    let listed: Value = serde_json::from_str(&stdio.read_stdout_line()?)?;
    let tools = listed
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("stdio tools/list omitted tools")?;
    assert!(!tools.is_empty(), "stdio viewer sees read tools");
    assert!(!tool_names(tools).any(|name| name == "kcc_config_save"));
    assert!(tools.iter().all(|tool| {
        tool.pointer("/annotations/readOnlyHint")
            .and_then(Value::as_bool)
            == Some(true)
    }));
    stdio.close_stdin();
    let (status, stderr) = stdio.wait()?;
    assert_eq!(status.code(), Some(0_i32), "{stderr}");
    let mut config_text = fs::read_to_string(&fixture.config)?;
    config_text = config_text.replace(
        "stdio_enabled = true\n",
        "stdio_enabled = true\nstdio_role = \"operator\"\n",
    );
    fs::write(&fixture.config, config_text)?;
    let mut operator_stdio = fixture.spawn_command(&["mcp", "stdio"])?;
    operator_stdio.write_line(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}))?;
    drop(operator_stdio.read_stdout_line()?);
    operator_stdio.write_line(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
    operator_stdio
        .write_line(&json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/list","params":{}}))?;
    let operator_list: Value = serde_json::from_str(&operator_stdio.read_stdout_line()?)?;
    let operator_tools = operator_list
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("stdio operator tools/list omitted tools")?;
    assert!(tool_names(operator_tools).any(|name| name == "kcc_config_save"));
    operator_stdio.close_stdin();
    let (operator_status, operator_stderr) = operator_stdio.wait()?;
    assert_eq!(operator_status.code(), Some(0_i32), "{operator_stderr}");
    drop(server);
    fixture.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn unknown_stdio_role_is_refused() -> TestResult {
    let fixture = Fixture::new(true).await?;
    let mut text = fs::read_to_string(&fixture.config)?;
    text = text.replace(
        "stdio_enabled = true\n",
        "stdio_enabled = true\nstdio_role = \"nosuchrole\"\n",
    );
    fs::write(&fixture.config, text)?;
    let process = fixture.spawn_command(&["mcp", "stdio"])?;

    let (status, stderr) = process.wait()?;

    assert_eq!(status.code(), Some(1_i32));
    assert!(
        stderr.contains("configured stdio role \"nosuchrole\" does not exist"),
        "{stderr}"
    );
    fixture.shutdown().await?;
    Ok(())
}

#[test]
fn disabled_stdio_exits_forbidden() -> TestResult {
    let directory = TempDir::new()?;
    let key_path = directory.path().join("master.key");
    write_master_key(&key_path)?;
    let config = directory.path().join("kcc.toml");
    fs::write(
        &config,
        "[web]\nenabled = false\n\n[mcp]\nstdio_enabled = false\n\n[state]\ndir = \"state\"\n",
    )?;
    let process = ChildGuard::spawn(
        &[
            "mcp",
            "stdio",
            "--config",
            config.to_str().ok_or("non-UTF-8 config path")?,
        ],
        directory.path(),
        &key_path,
    )?;

    let (status, stderr) = process.wait()?;

    assert_eq!(status.code(), Some(10_i32));
    assert!(stderr.contains("stdio transport is disabled"), "{stderr}");
    Ok(())
}

#[test]
fn non_loopback_plain_http_web_is_refused() -> TestResult {
    let directory = TempDir::new()?;
    let key_path = directory.path().join("master.key");
    write_master_key(&key_path)?;
    let config = directory.path().join("kcc.toml");
    fs::write(
        &config,
        "[server]\nlisten_addr = \"0.0.0.0\"\nlisten_port = 18081\n\n[web]\nenabled = true\n\n[state]\ndir = \"state\"\n",
    )?;
    let process = ChildGuard::spawn(
        &[
            "serve",
            "--config",
            config.to_str().ok_or("non-UTF-8 config path")?,
        ],
        directory.path(),
        &key_path,
    )?;

    let (status, stderr) = process.wait()?;

    assert_eq!(status.code(), Some(1_i32));
    assert!(
        stderr.contains("non-loopback Web UI requires TLS"),
        "{stderr}"
    );
    Ok(())
}
