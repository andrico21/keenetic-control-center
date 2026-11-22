//! `kcc serve` with the MCP settings page: a live change reaches new MCP sessions without
//! a restart, the dedicated listener starts from the page, and a restart that cannot bind
//! reverts with the settings file unchanged.
//!
//! On Linux every child runs with a 1 MiB main-thread stack (`ulimit -s 1024`), the size
//! Windows gives the main thread.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "serve_mcp_admin/browser.rs"]
mod browser;
#[path = "serve_mcp_admin/fixture.rs"]
mod fixture;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;

use core::time::Duration;
use std::net::TcpListener;

use browser::Browser;
use fixture::{Fixture, PASSWORD, TestResult};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use serve_port::free_ports;
use tokio::time::{interval, timeout};

/// The status fragment, polled with no deadline of its own.
const STATUS: &str = "/ui/admin/mcp/status?until=18446744073709551615";

/// How long a restart of the dedicated listener may take: the 1 s shutdown timeout plus
/// the 10 s health window, with room.
const RESTART: Duration = Duration::from_secs(30);

/// Polls the status fragment as the page does until it holds a message key, for at most
/// [`RESTART`]; the key.
async fn settled(client: &Client, browser: &Browser) -> TestResult<String> {
    timeout(RESTART, message_key(client, browser))
        .await
        .map_err(|_elapsed| "the restart never ended")?
}

/// Polls the status fragment every 200 ms until it holds a message key; the key.
async fn message_key(client: &Client, browser: &Browser) -> TestResult<String> {
    let mut ticks = interval(Duration::from_millis(200));
    loop {
        let _instant = ticks.tick().await;
        let fragment = browser.get(client, STATUS).await?;
        if let Some((_, tail)) = fragment.split_once("data-message-key=\"") {
            return Ok(tail.split_once('"').map_or(tail, |(key, _)| key).to_owned());
        }
    }
}

/// The settings revision the page's forms carry.
fn revision(html: &str) -> TestResult<String> {
    let (_, tail) = html
        .split_once("name=\"revision\" value=\"")
        .ok_or("no revision field")?;
    Ok(tail.split_once('"').ok_or("unterminated")?.0.to_owned())
}

/// The dedicated port `mcp_settings.json` holds.
fn saved_port(fixture: &Fixture) -> TestResult<Option<u64>> {
    let bytes = fixture.settings()?.ok_or("no mcp_settings.json")?;
    let document: Value = serde_json::from_slice(&bytes)?;
    Ok(document
        .pointer("/overrides/dedicated/port")
        .and_then(Value::as_u64))
}

/// Saves the Endpoints section with the dedicated listener on at `port`, as a page of
/// `revision` posts it; the answer's status and text.
async fn save_port(
    fixture: &Fixture,
    browser: &Browser,
    (port, revision): (u16, &str),
) -> TestResult<(StatusCode, String)> {
    let port_text = port.to_string();
    let pairs = [
        ("revision", revision),
        ("field", "dedicated.enabled"),
        ("dedicated.enabled", "on"),
        ("field", "dedicated.port"),
        ("dedicated.port", port_text.as_str()),
    ];
    let answer = browser
        .post(fixture.http(), "/ui/admin/mcp", &pairs)
        .await?;
    Ok((answer.status(), answer.text().await?))
}

/// Todo 27: a restart that moves the dedicated listener to another port shows the new
/// port, and no later Save moves it back.
///
/// The ended status carries the page's settings with the new port, a Save without edits
/// keeps it, and a Save from the page as it stood before the restart is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_port_shows_and_stays() -> TestResult {
    let fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let browser = fixture.sign_in(server.base()).await?;
    let [first, second] = free_ports()?;
    let opened = browser.get(fixture.http(), "/ui/admin/mcp").await?;
    let (asked, _) = save_port(&fixture, &browser, (first, &revision(&opened)?)).await?;
    assert_eq!(asked, StatusCode::OK);
    let applied = "web-admin-mcp-restart-applied";
    assert_eq!(settled(fixture.http(), &browser).await?, applied);
    let before = revision(&browser.get(fixture.http(), "/ui/admin/mcp").await?)?;
    let (moved, _) = save_port(&fixture, &browser, (second, &before)).await?;
    assert_eq!(moved, StatusCode::OK);
    assert_eq!(settled(fixture.http(), &browser).await?, applied);
    let shown = format!("name=\"dedicated.port\" type=\"number\" value=\"{second}\"");
    let ended = browser.get(fixture.http(), STATUS).await?;
    assert!(
        ended.contains(&shown),
        "the status brings the new port: {ended}"
    );
    let page = browser.get(fixture.http(), "/ui/admin/mcp").await?;
    assert!(page.contains(&shown), "the page shows the new port");
    let (kept, unchanged) = save_port(&fixture, &browser, (second, &revision(&page)?)).await?;
    assert_eq!(kept, StatusCode::OK);
    assert!(unchanged.contains("web-admin-mcp-unchanged"), "{unchanged}");
    let (stale, reload) = save_port(&fixture, &browser, (first, &before)).await?;
    assert_eq!(stale, StatusCode::CONFLICT);
    assert!(
        reload.contains("web-admin-mcp-restart-settings-changed"),
        "{reload}"
    );
    assert_eq!(saved_port(&fixture)?, Some(u64::from(second)));
    Ok(())
}

/// Todo 27: turning `allow_destructive` on in the page applies it live: a new MCP session
/// reaches the confirmation check instead of `destructive_disabled`, and no listener
/// restarted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allow_destructive_reaches_a_new_session_without_a_restart() -> TestResult {
    let fixture = Fixture::new().await?;
    let mut server = fixture.serve()?;
    let base = server.base().to_owned();
    assert!(
        fixture
            .reboot(&base)
            .await?
            .contains("destructive_disabled")
    );
    let browser = fixture.sign_in(&base).await?;
    let pairs = [
        ("field", "allow_destructive"),
        ("allow_destructive", "on"),
        ("password", PASSWORD),
    ];
    let saved = browser
        .post(fixture.http(), "/ui/admin/mcp", &pairs)
        .await?;
    assert_eq!(saved.status(), StatusCode::OK);
    assert!(
        saved
            .text()
            .await?
            .contains("data-message-key=\"web-admin-mcp-saved\""),
        "applied live"
    );
    let after = fixture.reboot(&base).await?;
    assert!(after.contains("confirm_required"), "{after}");
    let port = base.rsplit(':').next().ok_or("no port")?;
    assert_eq!(
        server.count(&format!("listening on 127.0.0.1:{port}")),
        1,
        "no restart"
    );
    assert!(
        fixture.settings()?.is_some(),
        "the supervisor saved the change"
    );
    Ok(())
}

/// Todo 27: enabling the dedicated listener in the page starts it; it answers MCP once the
/// status poll reports the restart applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_dedicated_listener_enabled_in_the_page_answers() -> TestResult {
    let fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let browser = fixture.sign_in(server.base()).await?;
    let [port] = free_ports()?;
    let port_text = port.to_string();
    let pairs = [
        ("field", "dedicated.enabled"),
        ("dedicated.enabled", "on"),
        ("field", "dedicated.port"),
        ("dedicated.port", port_text.as_str()),
    ];
    let asked = browser
        .post(fixture.http(), "/ui/admin/mcp", &pairs)
        .await?;
    assert_eq!(asked.status(), StatusCode::OK);
    assert_eq!(
        settled(fixture.http(), &browser).await?,
        "web-admin-mcp-restart-applied"
    );
    assert_eq!(fixture.initialize(port).await?, StatusCode::OK);
    Ok(())
}

/// Todo 27: enabling the dedicated listener on a port the test holds reverts with the
/// localized bind reason, leaves `mcp_settings.json` as it was, and a fresh `kcc serve`
/// on the same state directory starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_port_reverts_and_the_next_start_serves() -> TestResult {
    let fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let browser = fixture.sign_in(server.base()).await?;
    let held = TcpListener::bind(("127.0.0.1", 0))?;
    let port_text = held.local_addr()?.port().to_string();
    let before = fixture.settings()?;
    let pairs = [
        ("field", "dedicated.enabled"),
        ("dedicated.enabled", "on"),
        ("field", "dedicated.port"),
        ("dedicated.port", port_text.as_str()),
    ];
    let asked = browser
        .post(fixture.http(), "/ui/admin/mcp", &pairs)
        .await?;
    assert_eq!(asked.status(), StatusCode::OK);
    assert_eq!(
        settled(fixture.http(), &browser).await?,
        "web-admin-mcp-restart-bind"
    );
    assert_eq!(fixture.settings()?, before, "mcp_settings.json unchanged");
    drop(server);
    let again = fixture.serve()?;
    let page = fixture
        .sign_in(again.base())
        .await?
        .get(fixture.http(), "/ui/admin/mcp")
        .await?;
    assert!(page.contains("name=\"dedicated.enabled\" value=\"on\" aria-describedby=\"mcp-dedicated-enabled-source\">"), "still off");
    drop(held);
    Ok(())
}
