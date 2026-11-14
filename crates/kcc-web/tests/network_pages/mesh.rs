//! The mesh page.
//!
//! What each role sees, a member restart that needs the router name typed, and member
//! actions the router refuses, shown in its own words. The fake router knows no `mws`
//! command, so a refusal is injected for every action.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_testkit::FaultInjection;

use crate::support::{
    outcome::TestResult,
    page::{said, text},
    web::Fixture,
};

/// The page under test.
const PAGE: &str = "/ui/r/home/mesh";

/// Restarting the fixture's member.
pub(crate) const RESTART: &str = "/ui/r/home/mesh/action?name=Extender0&do=restart";

#[tokio::test]
async fn each_role_sees_the_members_and_only_its_actions() -> TestResult {
    let fixture = Fixture::new().await?;
    for (account, updates, restarts) in [
        ("viewer", false, false),
        ("operator", true, false),
        ("admin", true, true),
    ] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            said(Locale::En, keys::WEB_MESH_TITLE),
            "fixture-extender".to_owned(),
            "Extender0".to_owned(),
            "02:00:00:00:20:01".to_owned(),
            "<span class=\"status\" data-status=\"online\">".to_owned(),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(
            page.contains("mesh/action?name=Extender0&#38;do=check"),
            updates,
            "{account} check"
        );
        assert_eq!(
            page.contains("mesh/action?name=Extender0&#38;do=restart"),
            restarts,
            "{account} restart"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_update_check_refused_by_the_router_shows_its_words() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("update check", 1))
            .await?;
    let operator = fixture.login("operator").await?;
    let response = fixture
        .post(
            "/ui/r/home/mesh/action?name=Extender0&do=check",
            &operator,
            "",
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "answered");
    let body = text(response).await?;
    assert!(
        body.contains(&said(Locale::En, keys::WEB_KIT_REJECTED)),
        "localized: {body}"
    );
    let said_block = body
        .split_once("<ul class=\"router-said__list\">")
        .and_then(|(_, tail)| tail.split_once("</ul>"))
        .map(|(list, _)| list.to_owned())
        .ok_or("no router-said list")?;
    assert!(said_block.contains("<li>"), "the router's message");
    assert!(
        !said_block.contains("Extender0"),
        "no request body: {said_block}"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.mesh_update_check" && entry.outcome == "rci_error"),
        "audited"
    );
    let unknown = fixture
        .post(
            "/ui/r/home/mesh/action?name=Extender0&do=explode",
            &operator,
            "",
        )
        .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND, "unknown action");
    Ok(())
}
