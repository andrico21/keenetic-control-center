//! `McpApply` against a running kit server registered with the reload fan-out.

use core::{error::Error, net::SocketAddr};

use arc_swap::ArcSwap;
use kcc_app::{
    api_keys::{api_key_entries, create_api_key, expose_created_key},
    audit::AuditLog,
    backups::BackupStore,
    jobs::JobRunner,
    mcp_settings::{Effective, EnvOverrides, ListenerKind, McpBase},
    permissions::load_roles,
    persist::StateStore,
    poller::Poller,
    registry::RouterRegistry,
    secrets::MasterKey,
    settings::{Config, OutboundConfig, PrivacyConfig},
    workflow::ChangeWorkflow,
};
use kcc_mcp::KccMcp;
use kcc_web::admin::TransportReload;
use rmcp_server_kit::{
    auth::AuthConfig,
    rbac::RbacPolicy,
    transport::{McpServerConfig, serve_with_listener},
};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

use super::{Arc, McpApply};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// The effective settings of a kcc.toml whose `[mcp]` table is `mcp`.
fn effective(state: &StateStore, mcp: &str) -> TestResult<Effective> {
    let config = Config::from_toml_str(&format!("[mcp]\n{mcp}"))?;
    Ok(McpBase::new(&config, &EnvOverrides::default()).effective(state)?)
}

/// A handler on `effective` over an empty router registry.
async fn handler(state: &StateStore, effective: &Effective) -> TestResult<KccMcp> {
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let audit = AuditLog::spawn(state)?;
    let backups = Arc::new(BackupStore::new(
        state.clone(),
        MasterKey::from_bytes([3_u8; 32]),
    ));
    let workflow =
        ChangeWorkflow::new(state.clone(), Arc::clone(&registry), backups, audit.clone());
    let jobs = JobRunner::open(state.clone(), Arc::clone(&registry), audit).await?;
    let roles = load_roles(state)?;
    let admin = roles
        .iter()
        .find(|role| role.name == "admin")
        .cloned()
        .ok_or("no admin role")?;
    Ok(KccMcp::new(
        effective.settings().clone(),
        PrivacyConfig::default(),
        Arc::clone(&registry),
        workflow,
        jobs,
        Poller::new(registry),
        roles,
        admin,
    ))
}

/// The HTTP status of a sessionless `tools/call` of `tool` carrying `key`.
async fn call_status(address: SocketAddr, key: &str, tool: &str) -> TestResult<u16> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{tool}","arguments":{{}}}}}}"#
    );
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {key}\r\n\
         Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut status_line = String::new();
    let _: usize = BufReader::new(stream).read_line(&mut status_line).await?;
    Ok(status_line
        .split_whitespace()
        .nth(1)
        .ok_or("no status code")?
        .parse()?)
}

/// Todo 25: `apply` swaps the handler new sessions clone and rebuilds the RBAC policy
/// of a registered server from the new tools: a tool whose toolset was turned off is
/// refused by RBAC (403) at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_swaps_the_handler_and_rebuilds_rbac() -> TestResult {
    let directory = tempfile::TempDir::new()?;
    let state = StateStore::open(directory.path())?;
    let admin = load_roles(&state)?
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or("no admin role")?;
    let created = create_api_key(
        &state,
        &admin,
        "probe".to_owned(),
        "admin".to_owned(),
        0,
        None,
    )?;
    let key = expose_created_key(&created).to_owned();
    let with_raw = effective(&state, "toolsets = [\"core\", \"raw\"]\n")?;
    let first = handler(&state, &with_raw).await?;
    let rbac = Arc::new(RbacPolicy::new(&first.rbac_config()));
    let reload = Arc::new(TransportReload::new(
        state.clone(),
        first.tool_specs().to_vec(),
    ));
    let live = Arc::new(ArcSwap::from_pointee(first));
    let (registered, handle_ready) = oneshot::channel();
    let bridge = Arc::clone(&reload);
    let config = McpServerConfig::new("127.0.0.1:0", "kcc-live", "0.0.0")
        .with_auth(AuthConfig::with_keys(api_key_entries(&state)?))
        .with_rbac(rbac)
        .with_reload_callback(move |handle| {
            drop(registered.send(bridge.register(ListenerKind::Main, handle)));
        })
        .validate()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (ready, address_ready) = oneshot::channel();
    let factory = Arc::clone(&live);
    let server = tokio::spawn(serve_with_listener(
        listener,
        config,
        move || factory.load().as_ref().clone(),
        Some(ready),
        None,
    ));
    let address = address_ready.await?;
    handle_ready.await??;
    let admitted = call_status(address, &key, "kcc_rci_execute").await?;
    assert_ne!(admitted, 403, "RBAC admits the raw tool");

    McpApply::new(Arc::clone(&live), Arc::clone(&reload))
        .apply(&effective(&state, "toolsets = [\"core\"]\n")?)?;

    assert!(
        !live
            .load()
            .tool_specs()
            .iter()
            .any(|spec| spec.name == "kcc_rci_execute"),
        "new sessions start without the raw tool"
    );
    assert_eq!(
        call_status(address, &key, "kcc_rci_execute").await?,
        403,
        "RBAC refuses the raw tool"
    );
    assert_eq!(
        call_status(address, &key, "kcc_routers_list").await?,
        admitted,
        "RBAC still admits core tools"
    );
    server.abort();
    Ok(())
}

/// Todo 25: with `http_enabled` off, `apply` registers no tool for new sessions.
#[tokio::test]
async fn apply_without_http_registers_no_tool() -> TestResult {
    let directory = tempfile::TempDir::new()?;
    let state = StateStore::open(directory.path())?;
    let first = handler(&state, &effective(&state, "toolsets = [\"core\"]\n")?).await?;
    let reload = Arc::new(TransportReload::new(
        state.clone(),
        first.tool_specs().to_vec(),
    ));
    let live = Arc::new(ArcSwap::from_pointee(first));

    McpApply::new(Arc::clone(&live), reload).apply(&effective(
        &state,
        "http_enabled = false\ntoolsets = [\"core\"]\n",
    )?)?;

    assert_eq!(live.load().tool_specs().len(), 0);
    Ok(())
}
