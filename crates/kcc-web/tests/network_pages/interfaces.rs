//! The interfaces page.
//!
//! What each role sees, a description read back with the unsaved badge, a value refused
//! before anything is sent and a router refusal in the router's own words.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_testkit::FaultInjection;

use crate::{
    form, interface, said,
    support::{Fixture, ROUTER, TestResult, header_text, text},
};

/// The page under test.
const PAGE: &str = "/ui/r/home/network";

/// The Disable button of `Bridge0`.
pub(crate) const DISABLE_BRIDGE: &str =
    "hx-post=\"/ui/r/home/network/state?name=Bridge0&#38;state=down\"";

#[tokio::test]
async fn each_role_sees_the_interfaces_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    for (account, disables) in [("viewer", false), ("operator", false), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            said(Locale::En, keys::WEB_NETWORK_TITLE),
            "<span class=\"mono\">Bridge0</span>".to_owned(),
            "<span class=\"mono\">GigabitEthernet0/0</span>".to_owned(),
            "192.0.2.1/24".to_owned(),
            "href=\"/ui/r/home/internet\"".to_owned(),
            "aria-current=\"page\">".to_owned(),
            "hx-get=\"/ui/r/home/network/detail?name=Bridge0\"".to_owned(),
            "id=\"page-outcome\"".to_owned(),
            "<option value=\"home\" selected>".to_owned(),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(DISABLE_BRIDGE), disables, "{account} disable");
    }
    let viewer = fixture.login("viewer").await?;
    let refused = fixture
        .post(
            "/ui/r/home/network/state?name=Bridge0&state=up",
            &viewer,
            "",
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "the route checks");
    let dialog = fixture
        .get("/ui/r/home/network/description?name=Bridge0", &viewer)
        .await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "no dialog either");
    let missing = fixture.get("/ui/r/cottage/network", &viewer).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND, "unknown router");
    let sorted = text(
        fixture
            .get(&format!("{PAGE}?q=bridge&sort=type&dir=desc"), &viewer)
            .await?,
    )
    .await?;
    assert!(
        sorted.contains(">Bridge0</span>"),
        "the filter keeps Bridge0"
    );
    assert!(
        !sorted.contains(">GigabitEthernet0/0</span>"),
        "and drops the rest: {sorted}"
    );
    assert!(
        sorted.contains("aria-sort=\"descending\"><a class=\"sort\" href=\"/ui/r/home/network?q=bridge&#38;sort=type&#38;dir=asc\""),
        "the sort keeps the filter"
    );
    let ukrainian = fixture.login("ukrainian").await?;
    let localized = text(fixture.get(PAGE, &ukrainian).await?).await?;
    assert!(
        localized.contains(&said(Locale::Uk, keys::WEB_NETWORK_TITLE)),
        "the account's language"
    );
    Ok(())
}

#[tokio::test]
async fn a_description_is_read_back_with_the_unsaved_badge() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let path = "/ui/r/home/network/description?name=Bridge0";
    let dialog = fixture.get(path, &operator).await?;
    assert_eq!(dialog.status(), StatusCode::OK, "dialog");
    let shown = text(dialog).await?;
    assert!(
        shown.contains("value=\"Home network\""),
        "the dialog starts from the current value: {shown}"
    );
    let wanted = "Upstairs LAN";
    let response = fixture
        .post(path, &operator, &form(&[("value", wanted)]))
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "applied");
    assert_eq!(
        header_text(&response, "hx-trigger").as_deref(),
        Some("kcc:dialog-close"),
        "the dialog closes"
    );
    let body = text(response).await?;
    for expected in [
        said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
        "id=\"unsaved-badge\" hx-swap-oob=\"true\"".to_owned(),
        "id=\"net-region\" hx-swap-oob=\"true\"".to_owned(),
        format!("<span class=\"net-table__note\">{wanted}</span>"),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    let read_back = interface(&fixture, "Bridge0").await?;
    assert_eq!(
        read_back
            .get("description")
            .and_then(|value| value.as_str()),
        Some(wanted),
        "the router has it"
    );
    assert_eq!(fixture.backups()?, 1, "one pre-change backup");
    let audit = fixture.audit()?;
    assert!(
        audit
            .iter()
            .any(|entry| entry.action == "web.interface_description"
                && entry.outcome == "success"
                && entry.router.as_deref() == Some(ROUTER)),
        "audited"
    );
    assert!(
        audit.iter().any(|entry| entry.action == "router.change_cli"
            && entry.target.as_deref() == Some("interface description")),
        "the change workflow's own entry"
    );
    assert!(
        audit
            .iter()
            .all(|entry| !entry.params_redacted.to_string().contains(wanted)),
        "field names only"
    );
    Ok(())
}

#[tokio::test]
async fn an_invalid_description_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(PAGE, &operator).await?);
    let before = fixture.handle().request_count();
    let long = "x".repeat(129);
    let response = fixture
        .post(
            "/ui/r/home/network/description?name=Bridge0",
            &operator,
            &form(&[("value", &long)]),
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "field error"
    );
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "back into the dialog"
    );
    let body = text(response).await?;
    let rule = said(Locale::En, keys::WEB_SYSTEM_DESCRIPTION_ERROR);
    assert!(
        body.contains(&format!(
            "<p class=\"field__error\" id=\"net-value-error\">{rule}</p>"
        )),
        "the server's message: {body}"
    );
    assert!(
        body.contains(&format!(
            "required maxlength=\"128\" data-kcc-invalid=\"{rule}\""
        )),
        "the same rule for the browser's check"
    );
    assert!(body.contains(&format!("value=\"{long}\"")), "as typed");
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.interface_description"
                && entry.outcome == "validation_failed"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("description", 1))
            .await?;
    let operator = fixture.login("operator").await?;
    let response = fixture
        .post(
            "/ui/r/home/network/description?name=Bridge0",
            &operator,
            &form(&[("value", "Upstairs LAN")]),
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
        !said_block.contains("Upstairs"),
        "no request body: {said_block}"
    );
    assert!(!body.contains("unsaved-badge"), "no badge for a refusal");
    assert!(
        fixture.audit()?.iter().any(
            |entry| entry.action == "web.interface_description" && entry.outcome == "rci_error"
        ),
        "audited"
    );
    Ok(())
}
