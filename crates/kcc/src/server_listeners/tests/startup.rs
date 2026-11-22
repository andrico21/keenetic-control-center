//! The start: the dedicated listener serves no metrics, a taken dedicated port is skipped,
//! and unusable sign-in settings saved on the Web fall back to kcc.toml's.

use std::net::TcpListener;

use kcc_app::{
    mcp_settings::{ListenerKind, document::McpOverrides},
    settings::mcp_schema::MtlsMode,
};
use reqwest::StatusCode;

use super::{
    TestResult,
    client::{http, status},
    fixture::{Fixture, Setup, free_port},
};
use crate::server_listeners::build::{Keys, build};

/// `[mcp.dedicated]` enabled on `port`.
fn dedicated_on(port: u16) -> String {
    format!("[mcp.dedicated]\nenabled = true\nport = {port}\n")
}

/// Todo 26: the dedicated listener never serves metrics; the main one does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_main_listener_serves_metrics() -> TestResult {
    let fixture = Fixture::start(Setup {
        tail: dedicated_on(free_port()?),
        ..Setup::default()
    })
    .await?;
    let settings = fixture.saved()?;

    let main = build(
        &fixture.shared,
        ListenerKind::Main,
        &settings,
        Keys::Required,
    )?;
    let dedicated = build(
        &fixture.shared,
        ListenerKind::Dedicated,
        &settings,
        Keys::Required,
    )?;

    #[expect(
        deprecated,
        reason = "the kit exposes the metrics switch only as this field"
    )]
    let served = (
        main.config.as_inner().metrics_enabled,
        dedicated.config.as_inner().metrics_enabled,
    );
    assert_eq!(served, (true, false));
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a dedicated port taken at start skips the dedicated listener with the reason
/// in the status; the main listener serves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_taken_dedicated_port_is_skipped_at_start() -> TestResult {
    let held = TcpListener::bind(("127.0.0.1", 0))?;
    let fixture = Fixture::start(Setup {
        tail: dedicated_on(held.local_addr()?.port()),
        ..Setup::default()
    })
    .await?;

    let started = fixture.supervisor.status();

    assert_eq!(started.dedicated, None);
    assert!(started.skipped.is_some(), "{started:?}");
    assert_eq!(
        status(&http()?, fixture.main()?, "/healthz").await?,
        StatusCode::OK
    );
    drop(held);
    fixture.stop().await??;
    Ok(())
}

/// Todo 26: a main listener that cannot use the sign-in settings saved on the Web starts
/// with kcc.toml's (the saved `[mcp.dedicated]` is ignored too) and says so; the saved
/// file is not changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unusable_saved_sign_in_settings_fall_back_to_kcc_toml() -> TestResult {
    let mut saved = McpOverrides::default();
    saved.auth.main.mtls = Some(MtlsMode::Optional);
    saved.dedicated.enabled = Some(true);
    saved.dedicated.port = Some(free_port()?);
    let fixture = Fixture::start(Setup {
        saved: Some(saved),
        ..Setup::default()
    })
    .await?;

    let started = fixture.supervisor.status();

    assert!(started.fallback.is_some(), "{started:?}");
    assert_eq!(started.dedicated, None);
    assert_eq!(
        status(&http()?, fixture.main()?, "/healthz").await?,
        StatusCode::OK
    );
    assert_eq!(fixture.revision()?, 1);
    assert_eq!(fixture.saved()?.auth.main.mtls, MtlsMode::Optional);
    fixture.stop().await??;
    Ok(())
}
