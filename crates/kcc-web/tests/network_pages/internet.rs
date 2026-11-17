//! The internet connections page.
//!
//! What each role sees, a connection's settings, a new connection made of several lines in
//! one change, and a priority applied with the unsaved badge.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};

use crate::support::{
    outcome::TestResult,
    page::{form, header_text, said, text},
    web::Fixture,
};

/// The page under test.
pub(crate) const PAGE: &str = "/ui/r/home/internet";

#[tokio::test]
async fn each_role_sees_the_connections_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    for (account, changes) in [("viewer", false), ("operator", true), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            said(Locale::En, keys::WEB_INTERNET_TITLE),
            "<span class=\"mono\">ISP</span>".to_owned(),
            "203.0.113.11/24".to_owned(),
            said(Locale::En, keys::WEB_INTERNET_KIND_IPOE),
            said(Locale::En, keys::WEB_INTERNET_CONNECTED),
            said(Locale::En, keys::WEB_INTERNET_PING_CHECK),
            "hx-get=\"/ui/r/home/internet/settings?name=ISP\"".to_owned(),
            "aria-current=\"page\">".to_owned(),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(
            page.contains("hx-get=\"/ui/r/home/internet/create\""),
            changes,
            "{account} add"
        );
        assert_eq!(
            page.contains("hx-get=\"/ui/r/home/internet/delete?name=ISP\""),
            changes,
            "{account} delete"
        );
    }
    let viewer = fixture.login("viewer").await?;
    let refused = fixture
        .post(
            &format!("{PAGE}/create"),
            &viewer,
            &form(&[("kind", "pppoe"), ("name", "PPPoE0")]),
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::FORBIDDEN, "the route checks");
    let settings = text(
        fixture
            .get(&format!("{PAGE}/settings?name=ISP"), &viewer)
            .await?,
    )
    .await?;
    assert!(
        settings.contains(&said(Locale::En, keys::WEB_INTERNET_KIND_IPOE)),
        "the settings: {settings}"
    );
    assert!(!settings.contains("internet/edit/"), "viewer: no Edit");
    let operator = fixture.login("operator").await?;
    let editable = text(
        fixture
            .get(&format!("{PAGE}/settings?name=ISP"), &operator)
            .await?,
    )
    .await?;
    for control in [
        "hx-get=\"/ui/r/home/internet/edit/mtu?name=ISP\"",
        "hx-get=\"/ui/r/home/internet/edit/priority?name=ISP\"",
        "hx-get=\"/ui/r/home/internet/address?name=ISP\"",
    ] {
        assert!(editable.contains(control), "operator misses {control}");
    }
    Ok(())
}

#[tokio::test]
async fn a_new_connection_is_created_in_one_change() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let dialog = text(fixture.get(&format!("{PAGE}/create"), &operator).await?).await?;
    assert!(
        dialog.contains("<option value=\"ISP\">ISP</option>"),
        "the connections a tunnel may run over: {dialog}"
    );
    let response = fixture
        .post(
            &format!("{PAGE}/create"),
            &operator,
            &form(&[("kind", "ipoe"), ("name", "GigabitEthernet9"), ("via", "")]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "applied");
    let body = text(response).await?;
    for expected in [
        said(Locale::En, keys::WEB_KIT_DONE_UNSAVED),
        "id=\"unsaved-badge\" hx-swap-oob=\"true\"".to_owned(),
        "id=\"net-region\" hx-swap-oob=\"true\"".to_owned(),
    ] {
        assert!(body.contains(&expected), "missing {expected} in {body}");
    }
    let running = fixture.handle().running_config_text();
    assert!(
        running.contains("interface GigabitEthernet9") && running.contains("ip address dhcp"),
        "created with DHCP: {running}"
    );
    let audit = fixture.audit()?;
    assert!(
        audit.iter().any(|entry| entry.action == "router.change_cli"
            && entry.target.as_deref() == Some("interface, interface ip address dhcp")),
        "both lines in one change"
    );
    assert!(
        audit
            .iter()
            .any(|entry| entry.action == "web.wan_create" && entry.outcome == "success"),
        "audited"
    );
    let misnamed = fixture
        .post(
            &format!("{PAGE}/create"),
            &operator,
            &form(&[("kind", "pppoe"), ("name", "ISP")]),
        )
        .await?;
    assert_eq!(
        misnamed.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a tunnel name must start with its type"
    );
    assert!(
        text(misnamed)
            .await?
            .contains(&said(Locale::En, keys::WEB_INTERNET_NAME_ERROR)),
        "the rule"
    );
    Ok(())
}

/// W3-16: Add connection refuses the name of a connection the router already has.
#[tokio::test]
async fn an_existing_connection_name_is_refused() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let pppoe = form(&[("kind", "pppoe"), ("name", "PPPoE0")]);
    let created = fixture
        .post(&format!("{PAGE}/create"), &operator, &pppoe)
        .await?;
    assert_eq!(created.status(), StatusCode::OK, "created");
    let before = fixture.handle().running_config_text();
    let taken = fixture
        .post(&format!("{PAGE}/create"), &operator, &pppoe)
        .await?;
    assert_eq!(taken.status(), StatusCode::UNPROCESSABLE_ENTITY, "refused");
    assert!(
        text(taken)
            .await?
            .contains(&said(Locale::En, keys::WEB_INTERNET_NAME_EXISTS)),
        "the name is taken"
    );
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing sent"
    );
    Ok(())
}

#[tokio::test]
async fn a_priority_is_applied_and_stays_unsaved() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let response = fixture
        .post(
            &format!("{PAGE}/edit/priority?name=ISP"),
            &operator,
            &form(&[("value", "700")]),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "applied");
    assert_eq!(
        header_text(&response, "hx-trigger").as_deref(),
        Some("kcc:dialog-close"),
        "the dialog closes"
    );
    let body = text(response).await?;
    assert!(
        body.contains("id=\"unsaved-badge\" hx-swap-oob=\"true\""),
        "the unsaved badge: {body}"
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ip global 700"),
        "the router has it"
    );
    assert_eq!(fixture.backups()?, 1, "one pre-change backup");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.wan_priority" && entry.outcome == "success"),
        "audited"
    );
    Ok(())
}
