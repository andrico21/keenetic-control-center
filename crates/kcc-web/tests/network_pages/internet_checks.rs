//! The checks of the internet connections page.
//!
//! An MTU refused before anything is sent, a router refusal in the router's own words, and
//! Delete with the connection's name typed.

use axum::http::StatusCode;
use kcc_i18n::{keys, locale::Locale};
use kcc_testkit::FaultInjection;

use crate::{
    internet::PAGE,
    mesh::RESTART,
    support::{
        outcome::TestResult,
        page::{form, header_text, said, text},
        refusal::{Refusal, router_refusals},
        typed_name::{Ask, TypedName, typed_names},
        web::Fixture,
    },
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

/// The router's refusals of a connection priority, a network name and an interface
/// description show only the router's words.
#[tokio::test]
async fn a_router_refusal_shows_only_what_the_router_said() -> TestResult {
    router_refusals(&[
        Refusal {
            action: "web.wan_priority",
            refused: "ip global",
            account: "operator",
            post: (&format!("{PAGE}/edit/priority?name=ISP"), "value=700"),
            unsaid: "700",
            absent: &[],
            unchanged: true,
        },
        Refusal {
            action: "web.wifi_ssid",
            refused: "ssid",
            account: "operator",
            post: (
                "/ui/r/home/wifi/edit/ssid?name=WifiMaster1%2FAccessPoint0",
                "value=Upstairs",
            ),
            unsaid: "Upstairs",
            absent: &[],
            unchanged: true,
        },
        Refusal {
            action: "web.interface_description",
            refused: "description",
            account: "operator",
            post: (
                "/ui/r/home/network/description?name=Bridge0",
                "value=Upstairs+LAN",
            ),
            unsaid: "Upstairs",
            absent: &["unsaved-badge"],
            unchanged: true,
        },
    ])
    .await
}

/// A mesh member restart needs the router's name, a connection delete the connection's.
#[tokio::test]
async fn typed_names_are_exact() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("mws member", 1))
            .await?;
    let operator = fixture.login("operator").await?;
    let create = form(&[("kind", "pppoe"), ("name", "PPPoE0")]);
    drop(
        fixture
            .post(&format!("{PAGE}/create"), &operator, &create)
            .await?,
    );
    let running = fixture.handle().running_config_text();
    assert!(running.contains("interface PPPoE0"), "created: {running}");
    let confirmed = typed_names(
        &fixture,
        &[
            TypedName {
                action: "web.mesh_reboot",
                account: "admin",
                denied: Some("operator"),
                ask: Ask::Post(RESTART, ""),
                title: Some(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE),
                post: RESTART,
                fields: &[],
                names: ("Home", "home"),
                ran: ("rci_error", keys::WEB_KIT_REJECTED),
                rereads: false,
            },
            TypedName {
                action: "web.wan_delete",
                account: "operator",
                denied: None,
                ask: Ask::Get(&format!("{PAGE}/delete?name=PPPoE0")),
                title: None,
                post: &format!("{PAGE}/delete"),
                fields: &[("object", "PPPoE0")],
                names: ("pppoe0", "PPPoE0"),
                ran: ("success", keys::WEB_KIT_DONE_UNSAVED),
                rereads: false,
            },
        ],
    )
    .await?;
    let [restarted, deleted] = confirmed.as_slice() else {
        return Err("two rows".into());
    };
    assert!(
        restarted.body.contains("<ul class=\"router-said__list\">"),
        "the router's words: {}",
        restarted.body
    );
    assert_eq!(
        deleted.retarget.as_deref(),
        Some("#page-outcome"),
        "the outcome leaves the dialog"
    );
    assert!(
        !fixture.handle().running_config_text().contains("PPPoE0"),
        "gone"
    );
    Ok(())
}
