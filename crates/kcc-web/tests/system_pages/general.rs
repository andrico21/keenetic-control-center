//! The general page's time zone, time server and factory reset, with the system tabs.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    support::{
        outcome::TestResult,
        page::{en, form, text},
        typed_name::{Ask, TypedName, typed_names},
        web::Fixture,
    },
    users::{PAGE as USERS, add_lab, configured},
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
    let applied = text(
        fixture
            .post(
                &format!("{PAGE}/timezone"),
                &operator,
                &form(&[("value", "Europe/Berlin")]),
            )
            .await?,
    )
    .await?;
    assert!(
        applied.contains("data-tone=\"success\"") && applied.contains("Europe/Berlin"),
        "the verified zone is shown: {applied}"
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
        fixture.audited("web.system_ntp_server", "success")?,
        "audited"
    );
    Ok(())
}

/// A factory reset, an eject and a router user delete need their typed names.
#[tokio::test]
async fn typed_names_are_exact() -> TestResult {
    let fixture = Fixture::new().await?;
    let button = "hx-post=\"/ui/r/home/system/general/reset\"";
    for (account, shown) in [("viewer", false), ("operator", false), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let page = text(fixture.get(PAGE, &browser).await?).await?;
        assert_eq!(page.contains(button), shown, "{account}");
    }
    let admin = fixture.login("admin").await?;
    let unknown = fixture
        .post("/ui/r/home/system/storage/eject?media=Media9", &admin, "")
        .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND, "unknown medium");
    drop(add_lab(&fixture).await?);
    let (reset, eject) = (
        format!("{PAGE}/reset"),
        "/ui/r/home/system/storage/eject?media=Media0",
    );
    let refused = ("rci_error", keys::WEB_KIT_REJECTED);
    let confirmed = typed_names(
        &fixture,
        &[
            TypedName {
                action: "web.system_factory_reset",
                account: "admin",
                denied: Some("operator"),
                ask: Ask::Post(&reset, ""),
                title: Some(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE),
                post: &reset,
                fields: &[],
                names: ("Home", "home"),
                ran: refused,
                rereads: false,
            },
            TypedName {
                action: "web.storage_eject",
                account: "admin",
                denied: Some("operator"),
                ask: Ask::Post(eject, ""),
                title: Some(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE),
                post: eject,
                fields: &[],
                names: ("Home", "home"),
                ran: refused,
                rereads: true,
            },
            TypedName {
                action: "web.router_user_delete",
                account: "admin",
                denied: None,
                ask: Ask::Get(&format!("{USERS}/delete?name=lab")),
                title: None,
                post: &format!("{USERS}/delete"),
                fields: &[("object", "lab")],
                names: ("Lab", "lab"),
                ran: ("success", keys::WEB_KIT_DONE_UNSAVED),
                rereads: false,
            },
        ],
    )
    .await?;
    for answer in confirmed.iter().take(2) {
        assert!(
            answer.body.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
            "router said: {}",
            answer.body
        );
    }
    let deleted = confirmed.last().ok_or("three rows")?;
    assert_eq!(
        deleted.retarget.as_deref(),
        Some("#page-outcome"),
        "the outcome leaves the dialog"
    );
    assert!(configured(&fixture).await?.is_empty(), "gone");
    Ok(())
}
