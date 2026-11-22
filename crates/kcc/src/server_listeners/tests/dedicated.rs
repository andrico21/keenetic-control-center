//! The dedicated MCP listener: start, `/mcp`, stop, the endpoint rule, key reloads, mixed
//! saves, reverting both listeners, a non-loopback bind.

use core::net::{IpAddr, SocketAddr};
use std::net::{TcpListener, TcpStream, UdpSocket};

use kcc_app::{
    api_keys::ApiKeysDocument,
    mcp_settings::{ListenerKind, document::McpOverrides},
    settings::mcp_schema::{DedicatedTls, Endpoint},
};
use kcc_web::admin::AuthReload as _;
use reqwest::StatusCode;
use url::Url;

use super::{
    TestResult,
    client::{delete_error, http, initialize_status, session, tools},
    fixture::{Fixture, Setup, free_port},
};
use crate::server_listeners::{Restarted, RevertReason};

/// `[mcp.dedicated]` enabled on `port`.
fn dedicated_on(port: u16) -> String {
    format!("[mcp.dedicated]\nenabled = true\nport = {port}\n")
}

/// A fixture whose dedicated listener serves on a free port.
async fn with_dedicated(mcp: &str) -> TestResult<Fixture> {
    Fixture::start(Setup {
        mcp: mcp.to_owned(),
        tail: dedicated_on(free_port()?),
        ..Setup::default()
    })
    .await
}

/// Todo 26: enabling the dedicated listener starts it; it answers `/mcp` with an API key
/// and is registered for reloads; disabling it stops and unregisters it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dedicated_listener_starts_answers_and_stops_on_disable() -> TestResult {
    let fixture = Fixture::start(Setup::default()).await?;
    let port = free_port()?;
    let mut enable = McpOverrides::default();
    enable.dedicated.enabled = Some(true);
    enable.dedicated.port = Some(port);

    let started = fixture.supervisor.restart(fixture.plan(&enable)?).await?;
    let address = fixture.dedicated()?;
    let answered = initialize_status(&http()?, address, &fixture.key).await?;
    let registered = format!("{:?}", fixture.reload);
    let mut disable = McpOverrides::default();
    disable.dedicated.enabled = Some(false);
    let stopped = fixture.supervisor.restart(fixture.plan(&disable)?).await?;

    assert!(matches!(started, Restarted::Applied), "{started:?}");
    assert_eq!(address.port(), port);
    assert_eq!(answered, StatusCode::OK);
    assert!(
        registered.contains("registered: [Main, Dedicated]"),
        "{registered}"
    );
    assert!(matches!(stopped, Restarted::Applied), "{stopped:?}");
    assert_eq!(fixture.supervisor.status().dedicated, None);
    assert!(
        TcpStream::connect(address).is_err(),
        "the dedicated listener still serves"
    );
    assert!(format!("{:?}", fixture.reload).contains("registered: [Main]"));
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: with `endpoint = "dedicated"` the main listener's `/mcp` lists no tool while
/// the dedicated listener lists them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn endpoint_dedicated_leaves_the_main_listener_without_tools() -> TestResult {
    let fixture = with_dedicated("endpoint = \"dedicated\"").await?;
    let client = http()?;
    let (main, dedicated) = (fixture.main()?, fixture.dedicated()?);

    let on_main = tools(
        &client,
        (main, &fixture.key),
        &session(&client, main, &fixture.key).await?,
    )
    .await?;
    let on_dedicated = tools(
        &client,
        (dedicated, &fixture.key),
        &session(&client, dedicated, &fixture.key).await?,
    )
    .await?;

    assert_eq!(on_main, Vec::<String>::new());
    assert!(
        on_dedicated.iter().any(|name| name == "kcc_rci_delete"),
        "{on_dedicated:?}"
    );
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a key reload reaches both running servers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_keys_reaches_both_servers() -> TestResult {
    let fixture = with_dedicated("").await?;
    let client = http()?;
    let (main, dedicated) = (fixture.main()?, fixture.dedicated()?);
    assert_eq!(
        initialize_status(&client, main, &fixture.key).await?,
        StatusCode::OK
    );
    assert_eq!(
        initialize_status(&client, dedicated, &fixture.key).await?,
        StatusCode::OK
    );

    fixture.state.write(&ApiKeysDocument::default())?;
    fixture.reload.reload_keys()?;

    assert_eq!(
        initialize_status(&client, main, &fixture.key).await?,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        initialize_status(&client, dedicated, &fixture.key).await?,
        StatusCode::UNAUTHORIZED
    );
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a save that turns `allow_destructive` off and restarts the dedicated listener
/// also tightens a session already open on the main listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mixed_save_tightens_an_open_session() -> TestResult {
    let fixture = with_dedicated("").await?;
    let client = http()?;
    let main = fixture.main()?;
    let open = session(&client, main, &fixture.key).await?;
    let before = delete_error(&client, (main, &fixture.key), &open).await?;
    let mut change = McpOverrides::default();
    change.allow_destructive = Some(false);
    change.dedicated.port = Some(free_port()?);

    let restarted = fixture.supervisor.restart(fixture.plan(&change)?).await?;

    assert!(matches!(restarted, Restarted::Applied), "{restarted:?}");
    assert_ne!(before, "destructive_disabled");
    assert_eq!(
        delete_error(&client, (main, &fixture.key), &open).await?,
        "destructive_disabled"
    );
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a restart of both listeners whose dedicated bind fails reverts both.
///
/// The main listener serves its tools again and the dedicated one its old port; the live
/// settings and `mcp_settings.json` stay as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_dedicated_bind_reverts_both_listeners() -> TestResult {
    let fixture = with_dedicated("").await?;
    let old = fixture.dedicated()?;
    let held = TcpListener::bind(("127.0.0.1", 0))?;
    let mut change = McpOverrides::default();
    change.endpoint = Some(Endpoint::Dedicated);
    change.dedicated.port = Some(held.local_addr()?.port());
    change.toolsets = Some(vec!["core".to_owned()]);

    let restarted = fixture.supervisor.restart(fixture.plan(&change)?).await?;

    assert!(
        matches!(
            restarted,
            Restarted::Reverted(RevertReason::Bind {
                listener: ListenerKind::Dedicated,
                reason: _,
            })
        ),
        "{restarted:?}"
    );
    let client = http()?;
    let main = fixture.main()?;
    let listed = tools(
        &client,
        (main, &fixture.key),
        &session(&client, main, &fixture.key).await?,
    )
    .await?;
    assert!(
        listed.iter().any(|name| name == "kcc_rci_delete"),
        "{listed:?}"
    );
    assert_eq!(fixture.dedicated()?, old);
    assert_eq!(
        initialize_status(&client, old, &fixture.key).await?,
        StatusCode::OK
    );
    assert!(
        fixture
            .live
            .load()
            .tool_specs()
            .iter()
            .any(|spec| spec.name == "kcc_rci_delete")
    );
    assert_eq!(fixture.revision()?, 0);
    drop(held);
    fixture.stop().await??;
    Ok(())
}

/// This host's non-loopback address that routes towards the documentation network
/// (connecting a UDP socket sends nothing), if any.
fn routed_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.connect(("192.0.2.1", 9)).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// Todo 26: a dedicated listener bound to a non-loopback local address with a
/// self-signed certificate passes the health check, which probes the bound address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_loopback_bind_passes_the_health_check() -> TestResult {
    let Some(ip) = routed_address() else {
        tracing::warn!(
            "live-skip: this host has no route towards 192.0.2.1, so no non-loopback address"
        );
        return Ok(());
    };
    let port = TcpListener::bind((ip, 0))?.local_addr()?.port();
    let fixture = Fixture::start(Setup::default()).await?;
    let mut change = McpOverrides::default();
    change.dedicated.enabled = Some(true);
    change.dedicated.bind = Some(ip);
    change.dedicated.port = Some(port);
    change.dedicated.tls = Some(DedicatedTls::SelfSigned);
    change.dedicated.public_url = Some(Url::parse(&format!(
        "https://{}/",
        SocketAddr::new(ip, port)
    ))?);

    let restarted = fixture.supervisor.restart(fixture.plan(&change)?).await?;

    assert!(matches!(restarted, Restarted::Applied), "{restarted:?}");
    assert_eq!(fixture.dedicated()?, SocketAddr::new(ip, port));
    fixture.stop().await??;
    Ok(())
}
