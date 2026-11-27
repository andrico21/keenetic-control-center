//! The routing table page names the class of a failed router read.
//!
//! No answer, an HTTP error, a missing resource, an outbound-policy refusal, an answer
//! too large or one kcc cannot read, with the technical detail under its own label.

use axum::http::StatusCode;
use kcc_app::settings::OutboundConfig;
use kcc_i18n::keys;
use kcc_rci::engine::DEFAULT_RESPONSE_BYTES;
use kcc_testkit::{FakeRouter, FaultInjection, model::Profile};
use serde_json::json;

use crate::{
    get,
    support::{
        build::Setup,
        outcome::TestResult,
        page::{en, en_with, html},
        web::{Fixture, ROUTER},
    },
};

/// The IPv4 routing table view, which reads `show ip route`.
const TABLE: &str = "/ui/r/home/routing/table";

/// The routing table page over a fake router with `faults`, as an administrator sees it.
async fn table_with(faults: FaultInjection) -> TestResult<String> {
    let fixture = Fixture::with_faults(faults).await?;
    let admin = fixture.login("admin").await?;
    get(&fixture, &admin, TABLE, StatusCode::OK).await
}

/// Todo 8: an answer kcc cannot decode is told as unreadable, not as no answer, and the
/// detail names the command and the place in the answer, never its value.
#[tokio::test]
async fn an_unreadable_answer_names_the_command_and_the_field() -> TestResult {
    let fake = FakeRouter::builder(Profile::default())
        .show_fixture("ip/route", json!([{"static": "x"}]))
        .reached_directly()
        .build()?;
    let fixture = Fixture::with_router(fake).await?;
    let admin = fixture.login("admin").await?;
    let page = get(&fixture, &admin, TABLE, StatusCode::OK).await?;
    assert!(page.contains(&en(keys::WEB_KIT_UNREADABLE)), "{page}");
    assert!(page.contains(&en(keys::WEB_KIT_DETAILS)), "{page}");
    assert!(
        page.contains(&html("show ip route at $[0].static")),
        "{page}"
    );
    assert!(!page.contains(&en(keys::WEB_KIT_UNREACHABLE)), "{page}");
    Ok(())
}

/// Todo 8: a router that closed the connection did not answer, and the detail says how.
#[tokio::test]
async fn a_closed_connection_is_no_answer_with_its_cause() -> TestResult {
    let page = table_with(FaultInjection::default().close_before_answer("show/ip/route")).await?;
    assert!(page.contains(&en(keys::WEB_KIT_UNREACHABLE)), "{page}");
    assert!(
        page.contains(&html("the router closed the connection before answering")),
        "{page}"
    );
    Ok(())
}

/// Todo 8: an HTTP error status is told with its status, not as no answer.
#[tokio::test]
async fn an_http_error_names_its_status() -> TestResult {
    let page = table_with(FaultInjection::default().fail_read_matching("show/ip/route", 1)).await?;
    assert!(
        page.contains(&en_with(keys::WEB_KIT_HTTP_ERROR, &[("status", "500")])),
        "{page}"
    );
    assert!(!page.contains(&en(keys::WEB_KIT_UNREACHABLE)), "{page}");
    Ok(())
}

/// Todo 8: a resource the router answers 404 for by GET and by POST is not found.
#[tokio::test]
async fn a_missing_resource_is_not_found() -> TestResult {
    let page = table_with(FaultInjection::default().show_absent("show/ip/route")).await?;
    assert!(page.contains(&en(keys::WEB_KIT_NOT_FOUND)), "{page}");
    assert!(!page.contains(&en(keys::WEB_KIT_UNREACHABLE)), "{page}");
    Ok(())
}

/// Todo 8: an answer above the response limit is too large, not no answer.
#[tokio::test]
async fn an_oversized_answer_is_too_large() -> TestResult {
    let oversized = "x".repeat(DEFAULT_RESPONSE_BYTES.saturating_add(1));
    let page =
        table_with(FaultInjection::default().show_answers_text("show/ip/route", oversized)).await?;
    assert!(page.contains(&en(keys::WEB_KIT_TOO_LARGE)), "{page}");
    assert!(!page.contains(&en(keys::WEB_KIT_UNREACHABLE)), "{page}");
    Ok(())
}

/// Todo 8: a router outside `[outbound] allowed_networks` is refused by kcc's policy, and
/// the page says so instead of saying the router did not answer.
#[tokio::test]
async fn a_router_the_policy_refuses_names_the_policy() -> TestResult {
    let fake = FakeRouter::builder(Profile::default())
        .reached_directly()
        .build()?;
    let fixture = Setup {
        routers: vec![(ROUTER, fake)],
        outbound: OutboundConfig::default(),
        ..Setup::default()
    }
    .build()
    .await?;
    let admin = fixture.login("admin").await?;
    let page = get(&fixture, &admin, TABLE, StatusCode::OK).await?;
    assert!(page.contains(&en(keys::WEB_KIT_POLICY)), "{page}");
    assert!(!page.contains(&en(keys::WEB_KIT_UNREACHABLE)), "{page}");
    Ok(())
}
