//! The checks of the internet connections page.
//!
//! An MTU refused before anything is sent, a router refusal in the router's own words, and
//! Delete with the connection's name typed.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_testkit::FaultInjection;

use crate::{
    form,
    internet::PAGE,
    said,
    support::{Fixture, TestResult, header_text, text},
};

#[tokio::test]
async fn an_mtu_out_of_range_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    drop(fixture.get(PAGE, &operator).await?);
    let before = fixture.handle().request_count();
    let response = fixture
        .post(
            &format!("{PAGE}/edit/mtu?name=ISP"),
            &operator,
            &form(&[("value", "9000")]),
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
    let rule = said(Locale::En, keys::WEB_INTERNET_MTU_ERROR);
    assert!(
        body.contains(&format!(
            "<p class=\"field__error\" id=\"net-value-error\">{rule}</p>"
        )),
        "the server's message: {body}"
    );
    assert!(
        body.contains(&format!(
            "type=\"number\" value=\"9000\" autocomplete=\"off\" spellcheck=\"false\" required min=\"576\" max=\"1500\" step=\"1\" data-kcc-invalid=\"{rule}\""
        )),
        "the same rule for the browser's check"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.wan_mtu" && entry.outcome == "validation_failed"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("ip global", 1)).await?;
    let operator = fixture.login("operator").await?;
    let response = fixture
        .post(
            &format!("{PAGE}/edit/priority?name=ISP"),
            &operator,
            &form(&[("value", "700")]),
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
    assert!(!said_block.contains("700"), "no request body: {said_block}");
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.wan_priority" && entry.outcome == "rci_error"),
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn deleting_needs_the_connection_name() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    drop(
        fixture
            .post(
                &format!("{PAGE}/create"),
                &operator,
                &form(&[("kind", "pppoe"), ("name", "PPPoE0")]),
            )
            .await?,
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("interface PPPoE0"),
        "created"
    );
    let asked = text(
        fixture
            .get(&format!("{PAGE}/delete?name=PPPoE0"), &operator)
            .await?,
    )
    .await?;
    assert!(
        asked.contains("name=\"confirm_name\""),
        "the name field: {asked}"
    );
    let before = fixture.handle().request_count();
    let mistyped = fixture
        .post(
            &format!("{PAGE}/delete"),
            &operator,
            &form(&[
                ("object", "PPPoE0"),
                ("confirm", "yes"),
                ("confirm_name", "pppoe0"),
            ]),
        )
        .await?;
    assert_eq!(
        mistyped.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "names are exact"
    );
    assert!(
        text(mistyped)
            .await?
            .contains(&said(Locale::En, keys::WEB_ADMIN_ERROR_CONFIRM)),
        "the mismatch"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let deleted = fixture
        .post(
            &format!("{PAGE}/delete"),
            &operator,
            &form(&[
                ("object", "PPPoE0"),
                ("confirm", "yes"),
                ("confirm_name", "PPPoE0"),
            ]),
        )
        .await?;
    assert_eq!(deleted.status(), StatusCode::OK, "deleted");
    assert_eq!(
        header_text(&deleted, "hx-retarget").as_deref(),
        Some("#page-outcome"),
        "the outcome leaves the dialog"
    );
    assert!(
        !fixture.handle().running_config_text().contains("PPPoE0"),
        "gone"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.wan_delete" && entry.outcome == "success"),
        "audited"
    );
    Ok(())
}
