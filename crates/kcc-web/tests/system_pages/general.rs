//! The general page's time zone, time server and factory reset, with the system tabs.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    audited, en, form, html,
    support::{Fixture, ROUTER, TestResult, header_text, text},
};

/// The page under test.
const PAGE: &str = "/ui/r/home/system/general";

#[tokio::test]
async fn time_zone_and_time_server_change_through_their_dialogs() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let page = text(fixture.get(PAGE, &operator).await?).await?;
    for shown in [
        "hx-get=\"/ui/r/home/system/general/timezone\"",
        "hx-get=\"/ui/r/home/system/general/ntp_server\"",
        "<a class=\"tabs__link\" href=\"/ui/r/home/system/general\" aria-current=\"page\">",
    ] {
        assert!(page.contains(shown), "missing {shown}");
    }
    let dialog = text(fixture.get(&format!("{PAGE}/timezone"), &operator).await?).await?;
    assert!(dialog.contains("value=\"UTC\""), "current zone: {dialog}");
    let before = fixture.handle().request_count();
    let refused = fixture
        .post(
            &format!("{PAGE}/timezone"),
            &operator,
            &form(&[("value", "Europe Berlin")]),
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY, "422");
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SYSTEM_TIMEZONE_ERROR)),
        "the rule"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let ignored = text(
        fixture
            .post(
                &format!("{PAGE}/timezone"),
                &operator,
                &form(&[("value", "Europe/Berlin")]),
            )
            .await?,
    )
    .await?;
    let mut args = FluentArgs::new();
    args.set("field", "/tz/locality");
    let read_back = html(&tr(
        Locale::En,
        keys::WEB_KIT_VERIFICATION_FAILED,
        Some(&args),
    ));
    assert!(
        ignored.contains(&read_back),
        "the catalog took the zone, the fake kept UTC: {ignored}"
    );
    let server = text(
        fixture
            .post(
                &format!("{PAGE}/ntp_server"),
                &operator,
                &form(&[("value", "pool.ntp.org")]),
            )
            .await?,
    )
    .await?;
    assert!(
        server.contains("data-tone=\"success\""),
        "applied: {server}"
    );
    assert!(
        audited(&fixture, "web.system_ntp_server", "success")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn factory_reset_needs_the_exact_router_name() -> TestResult {
    let fixture = Fixture::new().await?;
    let reset = format!("{PAGE}/reset");
    let button = "hx-post=\"/ui/r/home/system/general/reset\"";
    for (account, shown) in [("viewer", false), ("operator", false), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let page = text(fixture.get(PAGE, &browser).await?).await?;
        assert_eq!(page.contains(button), shown, "{account}");
    }
    let operator = fixture.login("operator").await?;
    let denied = fixture.post(&reset, &operator, "").await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN, "operator");
    let admin = fixture.login("admin").await?;
    let asked = fixture.post(&reset, &admin, "").await?;
    assert_eq!(
        header_text(&asked, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "dialog"
    );
    assert!(
        text(asked)
            .await?
            .contains(&en(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
        "destructive"
    );
    let before = fixture.handle().request_count();
    let mistyped = text(
        fixture
            .post(&reset, &admin, "confirm=yes&confirm_name=Home")
            .await?,
    )
    .await?;
    let mut args = FluentArgs::new();
    args.set("router", ROUTER);
    let mismatch = html(&tr(
        Locale::En,
        keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
        Some(&args),
    ));
    assert!(mistyped.contains(&mismatch), "refused: {mistyped}");
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let refused = text(
        fixture
            .post(&reset, &admin, "confirm=yes&confirm_name=home")
            .await?,
    )
    .await?;
    assert!(
        refused.contains(&en(keys::WEB_KIT_REJECTED)),
        "the fake does not reset: {refused}"
    );
    assert!(
        refused.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
        "router said"
    );
    assert!(
        audited(&fixture, "web.system_factory_reset", "rci_error")?,
        "audited"
    );
    Ok(())
}
