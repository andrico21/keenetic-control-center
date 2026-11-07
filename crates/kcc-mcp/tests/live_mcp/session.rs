//! The shared smoke: gate, in-process MCP session, reads, and the guarded write segment.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use alloc::sync::Arc;
use core::{error::Error, str::from_utf8};
use std::path::{Path, PathBuf};

use kcc_app::{
    audit::AuditLog,
    backups::BackupStore,
    jobs::JobRunner,
    permissions::{Permission, Role},
    persist::StateStore,
    poller::Poller,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
    settings::{Config, McpConfig, OutboundConfig, PrivacyConfig},
    workflow::ChangeWorkflow,
};
use kcc_config::config_text::normalize;
use kcc_mcp::KccMcp;
use kcc_rci::{ConfigKind, RciBody, RciClient, RciPath, capabilities::RouterInfo};
use kcc_testkit::{
    capture::{connect, verify_serial},
    live_matrix::Run,
};
use rmcp::{
    ServiceExt as _,
    model::CallToolRequestParams,
    service::{RoleClient, RunningService},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::duplex;
use url::Url;

/// Test result.
pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Locally administered MAC of the probe known host.
const MAC: &str = "02:00:00:00:51:02";

/// The router and its gates.
pub(crate) struct Target {
    /// Router origin.
    pub url: String,
    /// Router account.
    pub login: String,
    /// Router password.
    pub password: SecretString,
    /// Password file, for the registry.
    pub password_file: PathBuf,
    /// Allowed serials.
    pub allowed: Vec<String>,
    /// kcc configuration holding the `test_device = true` profile; `None` reads only.
    pub write_config: Option<PathBuf>,
    /// Permits loopback routers (hermetic tests only).
    pub allow_loopback: bool,
}

/// What the smoke did.
pub(crate) struct Smoke {
    /// Matrix identity of the router.
    pub run: Run,
    /// Whether the write segment ran.
    pub wrote: bool,
}

/// Whether the profile for `url` in `config` is a test device.
fn test_device(config: &Path, url: &str) -> TestResult<bool> {
    let wanted = url.trim_end_matches('/');
    Ok(Config::load(config)?
        .routers
        .iter()
        .any(|profile| profile.url.as_str().trim_end_matches('/') == wanted && profile.test_device))
}

/// Runs the smoke: profile check, serial check, reads, then the write segment if admitted.
// NOT cancel-safe: the admitted write segment mutates the router under its fail-safe timer.
pub(crate) async fn smoke(target: Target) -> TestResult<Smoke> {
    let write = match &target.write_config {
        Some(config) if test_device(config, &target.url)? => true,
        Some(_config) => return Err("router profile is not marked test_device = true".into()),
        None => false,
    };
    let connection = connect(
        target.url.parse()?,
        target.login.clone(),
        target.password.clone(),
        target.allow_loopback,
    )
    .await?;
    let serial = verify_serial(&connection.client, &target.allowed).await?;
    let info = RouterInfo::detect(&connection.session, &connection.router).await?;
    let (_directory, session) = open(&target, write).await?;
    for (tool, arguments) in [
        ("kcc_router_info", json!({"host": "lab"})),
        ("kcc_system_read", json!({"host": "lab", "op": "version"})),
        ("kcc_interfaces_read", json!({"host": "lab", "op": "list"})),
        ("kcc_clients_read", json!({"host": "lab", "op": "list"})),
        (
            "kcc_routing_read",
            json!({"host": "lab", "op": "ipv4_routes"}),
        ),
        ("kcc_config_state", json!({"host": "lab"})),
    ] {
        drop(call(&session, tool, arguments).await?);
    }
    if write {
        write_segment(&session, &connection.client).await?;
    }
    drop(session.cancel().await?);
    Ok(Smoke {
        run: Run::observed(&serial, &info),
        wrote: write,
    })
}

/// Registers a `02:` known host through MCP, reads it back, removes it, and compares the
/// normalized running configuration under the fail-safe timer, disarmed only on a match.
// NOT cancel-safe: mutates the router.
async fn write_segment(session: &Session, client: &RciClient) -> TestResult {
    let before = running(client).await?;
    drop(
        client
            .parse("system configuration fail-safe timer reboot 900")
            .await?,
    );
    let registered = async || -> TestResult<bool> {
        let list = call(
            session,
            "kcc_clients_read",
            json!({"host": "lab", "op": "list"}),
        )
        .await?;
        Ok(list.to_string().contains(MAC))
    };
    let register = json!({"host": "lab", "op": "register", "mac": MAC, "value": "kcc-live-51"});
    drop(call(session, "kcc_clients_write", register).await?);
    if !registered().await? {
        return Err("MCP client write read-back failed".into());
    }
    let remove = json!({"host": "lab", "op": "remove", "mac": MAC});
    drop(call(session, "kcc_clients_write", remove).await?);
    if running(client).await? != before {
        return Err("running-config differs after the MCP write segment".into());
    }
    drop(
        client
            .parse("no system configuration fail-safe timer")
            .await?,
    );
    Ok(())
}

/// The normalized running configuration.
// cancel-safe: one read.
async fn running(client: &RciClient) -> TestResult<String> {
    let bytes = client.download_config(ConfigKind::Running).await?;
    Ok(normalize(from_utf8(bytes.expose_secret())?)?)
}

/// Reads a router's serial through `show identification`.
// cancel-safe: one read.
pub(crate) async fn read_serial(target: &Target) -> TestResult<String> {
    let connection = connect(
        target.url.parse()?,
        target.login.clone(),
        target.password.clone(),
        target.allow_loopback,
    )
    .await?;
    let path = RciPath::from_segments(["show", "identification"])?;
    let RciBody::Json(response) = connection.client.get(&path, &()).await? else {
        return Err("expected JSON identification".into());
    };
    Ok(response
        .value
        .get("serial")
        .and_then(Value::as_str)
        .ok_or("router has no serial")?
        .to_owned())
}

/// One connected client session.
type Session = RunningService<RoleClient, ()>;

/// Calls `tool` and returns its JSON payload, failing on a tool error.
// NOT cancel-safe: write tools may apply before cancellation.
async fn call(session: &Session, tool: &str, arguments: Value) -> TestResult<Value> {
    let Value::Object(object) = arguments else {
        return Err("arguments must be an object".into());
    };
    let params = CallToolRequestParams::new(tool.to_owned()).with_arguments(object);
    let result = session.call_tool(params).await?;
    let text = result
        .content
        .first()
        .and_then(|content| content.as_text())
        .map(|content| content.text.clone())
        .ok_or("tool returned no text")?;
    if result.is_error == Some(true) {
        return Err(format!("{tool} failed: {text}").into());
    }
    Ok(serde_json::from_str(&text)?)
}

/// Registers the router as `lab` on temporary state and connects a session; write toolsets
/// are enabled only for an admitted test device.
// NOT cancel-safe: writes temporary state and spawns the server task.
async fn open(target: &Target, write: bool) -> TestResult<(TempDir, Session)> {
    let directory = TempDir::new()?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = target.allow_loopback;
    let registry = Arc::new(RouterRegistry::new(state.clone(), &[], &outbound)?);
    let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
    let mut profile = ManagedRouterProfile::new(
        "lab".to_owned(),
        Url::parse(&target.url)?,
        target.login.clone(),
        target.password_file.clone(),
    );
    profile.test_device = write;
    registry.create(&admin, profile).await?;
    let backups = Arc::new(BackupStore::new(state.clone(), MasterKey::generate()?));
    let audit = AuditLog::spawn(&state)?;
    let workflow =
        ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
    let jobs = JobRunner::open(state, Arc::clone(&registry)).await?;
    let poller = Poller::new(Arc::clone(&registry));
    let mut config = McpConfig::default();
    config.toolsets = if write {
        vec!["core".to_owned(), "network-write".to_owned()]
    } else {
        vec!["core".to_owned()]
    };
    let server = KccMcp::new(
        config,
        PrivacyConfig::default(),
        registry,
        workflow,
        jobs,
        poller,
        vec![admin.clone()],
        admin,
    )
    .with_audit(audit);
    let (server_io, client_io) = duplex(1 << 20);
    drop(tokio::spawn(async move {
        if let Ok(running) = server.serve(server_io).await {
            drop(running.waiting().await);
        }
    }));
    let session = ().serve(client_io).await?;
    Ok((directory, session))
}
