//! Raw changes that are both destructive and management changes.
//!
//! Such a change asks once, in the dialog that explains the recovery timer, for the typed
//! router name, and runs inside the timer when that dialog is submitted; each stake alone
//! keeps its own dialog.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::use_debug,
    reason = "test code is not rendered API documentation; a test fails by panicking"
)]
#[path = "destructive_management/single_stake.rs"]
mod single_stake;

use std::io::{self, Write as _};

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::{FakeRouter, migration, model::Profile};

use crate::support::{
    outcome::TestResult,
    page::{en, form, header_text, html, text},
    web::{Browser, Fixture, ROUTER},
};

/// The CLI console's send endpoint.
const CLI: &str = "/ui/r/home/console/cli/send";

/// The RCI console's send endpoint.
const RCI: &str = "/ui/r/home/console/rci/send";

/// The dialog's router-name field.
const NAME_FIELD: &str = "name=\"confirm_name\"";

/// One raw request as its page sends it before any confirmation: the endpoint, the page
/// form's fields and the region a refusal lands in.
type Raw = (
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static str,
);

/// Requests that are destructive and change how kcc reaches the router: two console
/// lines, two console batches and the explorer's removal of the management bridge.
const BOTH: [Raw; 5] = [
    (CLI, &[("line", "no interface Bridge0")], "#cli-result"),
    (CLI, &[("line", "no service telnet")], "#cli-result"),
    (
        RCI,
        &[
            ("method", "POST"),
            ("path", ""),
            ("body", r#"[{"interface":{"name":"Bridge0","no":true}}]"#),
        ],
        "#rci-result",
    ),
    (
        RCI,
        &[
            ("method", "POST"),
            ("path", ""),
            ("body", r#"[{"service":{"http":{"no":true}}}]"#),
        ],
        "#rci-result",
    ),
    (
        "/ui/r/home/explorer/execute",
        &[
            ("path", "interface"),
            ("a.name", "Bridge0"),
            ("a.no", "true"),
        ],
        "#explorer-result",
    ),
];

/// The Web UI over a fake router in `mode`, the administrator and a raw writer signed in
/// and the router's catalog facts loaded.
async fn signed_in(mode: &str) -> TestResult<(Fixture, Browser, Browser)> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some(mode.to_owned());
    let fixture = Fixture::with_router(
        FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario),
    )
    .await?;
    let admin = fixture.login("admin").await?;
    let writer = fixture.login("raw-writer").await?;
    drop(fixture.get("/ui/r/home/console/cli", &admin).await?);
    Ok((fixture, admin, writer))
}

/// The recovery timer's arm and disarm lines in `mode`.
fn bracket(mode: &str) -> (&'static str, &'static str) {
    if mode == "router" {
        (
            "system configuration fail-safe timer reboot 300",
            "no system configuration fail-safe timer",
        )
    } else {
        ("system reboot 300", "no system reboot")
    }
}

/// The marker of the dialog paragraph worded by `key`.
fn marker(key: MessageKey) -> String {
    format!("data-message-key=\"{}\"", key.id())
}

/// `key` in English for the router `home`, escaped as the page shows it.
fn said(key: MessageKey) -> String {
    let mut args = FluentArgs::new();
    args.set("router", ROUTER);
    args.set("name", ROUTER);
    html(&tr(Locale::En, key, Some(&args)))
}

/// The form the browser posts when `dialog` is confirmed with `typed` as the name.
///
/// The page form's `fields` and the dialog's own fields: a dialog without the name field
/// sends no name, whatever the user would type.
fn submitted(dialog: &str, fields: &[(&str, &str)], typed: &str) -> String {
    let mut pairs: Vec<(&str, &str)> = fields.to_vec();
    if dialog.contains("<input type=\"hidden\" name=\"confirm\" value=\"yes\">") {
        pairs.push(("confirm", "yes"));
    }
    if dialog.contains(NAME_FIELD) {
        pairs.push(("confirm_name", typed));
    }
    form(&pairs)
}

/// `raw` from a role without `Destructive`: the refusal in its region, nothing sent.
async fn refused(fixture: &Fixture, browser: &Browser, raw: Raw) -> TestResult {
    let (endpoint, fields, region) = raw;
    let before = fixture.handle().request_count();
    let response = fixture.post(endpoint, browser, &form(fields)).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "{fields:?}");
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some(region),
        "{fields:?}"
    );
    let body = text(response).await?;
    assert!(body.contains(&marker(keys::WEB_REFUSAL_TITLE)), "{body}");
    assert_eq!(fixture.handle().request_count(), before, "{fields:?}");
    Ok(())
}

/// The first answer to `raw` from `browser`: a dialog, and nothing sent.
async fn first_dialog(fixture: &Fixture, browser: &Browser, raw: Raw) -> TestResult<String> {
    let (endpoint, fields, _) = raw;
    let before = fixture.handle().request_count();
    let response = fixture.post(endpoint, browser, &form(fields)).await?;
    assert_eq!(response.status(), StatusCode::OK, "{fields:?}");
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "a dialog first: {fields:?}"
    );
    let dialog = text(response).await?;
    assert_eq!(
        fixture.handle().request_count(),
        before,
        "unsent: {fields:?}"
    );
    Ok(dialog)
}

/// Submits `dialog` for `raw` as the browser does.
///
/// The router name is typed when the dialog has the field. Returns the outcome's
/// headline, the router requests it caused and the parser lines among them.
async fn confirm(
    fixture: &Fixture,
    browser: &Browser,
    raw: Raw,
    dialog: &str,
) -> TestResult<(String, usize, Vec<String>)> {
    let (endpoint, fields, _) = raw;
    let before = fixture.handle().request_log().len();
    let response = fixture
        .post(endpoint, browser, &submitted(dialog, fields, ROUTER))
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "{fields:?}");
    assert_eq!(
        header_text(&response, "hx-trigger").as_deref(),
        Some("kcc:dialog-close"),
        "it ran and the dialog closes: {fields:?}"
    );
    let outcome = text(response).await?;
    assert!(outcome.contains("<section class=\"outcome\""), "{outcome}");
    let headline = outcome
        .split_once("<p class=\"notice__title\">")
        .and_then(|(_, tail)| tail.split_once("</p>"))
        .map(|(title, _)| title.to_owned())
        .ok_or("no outcome headline")?;
    let log = fixture.handle().request_log();
    let lines = log
        .iter()
        .skip(before)
        .filter_map(|record| record.command().map(str::to_owned))
        .collect();
    Ok((headline, log.len().saturating_sub(before), lines))
}

/// A destructive management request asks for the typed name in the timer's dialog.
///
/// It asks once; a wrong name asks again and sends nothing; the dialog's own submit
/// applies the request inside the timer of the router's mode. A role without
/// `Destructive` is still refused unsent.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn destructive_management_requests_ask_for_the_name_and_run_inside_the_timer() -> TestResult {
    for mode in ["router", "extender"] {
        let (arm, disarm) = bracket(mode);
        for raw in BOTH {
            let (fixture, admin, writer) = signed_in(mode).await?;
            refused(&fixture, &writer, raw).await?;
            let dialog = first_dialog(&fixture, &admin, raw).await?;
            let help = format!(
                "id=\"confirm-name-help\">{}<",
                said(keys::WEB_ADMIN_CONFIRM_HELP)
            );
            for expected in [
                marker(keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TEXT),
                NAME_FIELD.to_owned(),
                help,
                "button--danger".to_owned(),
            ] {
                assert!(
                    dialog.contains(&expected),
                    "{mode} {raw:?}: {expected}: {dialog}"
                );
            }
            let destructive = marker(keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TEXT);
            assert!(!dialog.contains(&destructive), "one dialog: {dialog}");
            let before = fixture.handle().request_count();
            let mistyped = submitted(&dialog, raw.1, "Home");
            let again = text(fixture.post(raw.0, &admin, &mistyped).await?).await?;
            assert!(
                again.contains(&said(keys::WEB_EXPLORER_CONFIRM_NAME_ERROR))
                    && again.contains(NAME_FIELD),
                "asked again: {again}"
            );
            assert_eq!(fixture.handle().request_count(), before, "unsent: {raw:?}");
            let (headline, sent, lines) = confirm(&fixture, &admin, raw, &dialog).await?;
            assert_eq!(headline, en(keys::WEB_EXPLORER_DONE_UNSAVED), "{raw:?}");
            assert_eq!(lines.first().map(String::as_str), Some(arm), "{lines:?}");
            assert_eq!(lines.last().map(String::as_str), Some(disarm), "{lines:?}");
            assert!(!fixture.handle().recovery_armed(), "disarmed: {raw:?}");
            writeln!(
                io::stderr(),
                "BOTH {mode} {} {:?}: raw-writer 403 refusal, 0 sent; admin dialog management \
                 text + name field + help + danger, 0 sent; wrong name asked again, 0 sent; \
                 confirmed 200 dialog-close \"{headline}\", {sent} router requests, lines \
                 {lines:?}",
                raw.0,
                raw.1
            )?;
        }
    }
    Ok(())
}
