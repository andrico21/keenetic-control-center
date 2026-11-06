//! The RCI and CLI consoles, including the R-MCP2 incident payload.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::FaultInjection;

use crate::{
    INCIDENT, en, form, html,
    support::{Fixture, TestResult, header_text, text},
};

/// The RCI console rejects the R-MCP2 incident payload with the validation message and
/// never sends it.
#[tokio::test]
async fn the_rci_console_rejects_the_incident_payload_unsent() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let page = text(fixture.get("/ui/r/home/console/rci", &browser).await?).await?;
    assert!(page.contains("id=\"rci-body\""), "console");
    let before = fixture.handle().request_count();
    let request = form(&[
        ("method", "POST"),
        ("path", ""),
        ("body", INCIDENT),
        ("confirm", "yes"),
    ]);
    let checked = text(
        fixture
            .post("/ui/r/home/console/rci/check", &browser, &request)
            .await?,
    )
    .await?;
    let mut args = FluentArgs::new();
    args.set("field", "ip.route");
    let message = html(&tr(
        Locale::En,
        keys::WEB_EXPLORER_ISSUE_OBJECT,
        Some(&args),
    ));
    assert!(checked.contains(&message), "validation message: {checked}");
    let sent = fixture
        .post("/ui/r/home/console/rci/send", &browser, &request)
        .await?;
    assert_eq!(sent.status(), StatusCode::UNPROCESSABLE_ENTITY, "refused");
    assert_eq!(
        header_text(&sent, "hx-retarget").as_deref(),
        Some("#rci-check"),
        "shown in the check region, not repeated below"
    );
    assert!(
        text(sent).await?.contains(&message),
        "the same message on send"
    );
    assert_eq!(
        fixture.handle().request_count(),
        before,
        "the router received nothing"
    );
    assert!(
        fixture
            .audit()?
            .iter()
            .any(|entry| entry.action == "web.console_rci" && entry.outcome == "validation_failed"),
        "audited"
    );
    Ok(())
}

/// The RCI console reads with GET and sends a validated batch through the workflow.
#[tokio::test]
async fn the_rci_console_reads_and_sends_batches() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    let read = text(
        fixture
            .post(
                "/ui/r/home/console/rci/send",
                &browser,
                &form(&[("method", "GET"), ("path", "show version"), ("body", "")]),
            )
            .await?,
    )
    .await?;
    assert!(
        read.contains(&html("\"hw_id\": \"KN-1811\"")),
        "read: {read}"
    );
    let batch = r#"[{"ip":{"hotspot":{"host":{"mac":"02:00:00:00:00:97","permit":true}}}},{"show":{"version":{}}}]"#;
    let checked = text(
        fixture
            .post(
                "/ui/r/home/console/rci/check",
                &browser,
                &form(&[("method", "POST"), ("path", ""), ("body", batch)]),
            )
            .await?,
    )
    .await?;
    assert!(
        checked.contains("All 2 requests pass catalog validation."),
        "valid batch: {checked}"
    );
    let sent = text(
        fixture
            .post(
                "/ui/r/home/console/rci/send",
                &browser,
                &form(&[
                    ("method", "POST"),
                    ("path", ""),
                    ("body", batch),
                    ("confirm", "yes"),
                ]),
            )
            .await?,
    )
    .await?;
    assert!(
        sent.contains(&en(keys::WEB_EXPLORER_DONE_UNSAVED)),
        "sent: {sent}"
    );
    assert!(
        fixture
            .handle()
            .settings_snapshot()
            .to_string()
            .contains("02:00:00:00:00:97"),
        "applied"
    );
    Ok(())
}

/// The CLI console maps lines to catalog commands and refuses unknown ones unless an
/// administrator escapes validation.
#[tokio::test]
async fn the_cli_console_maps_lines_and_refuses_unknown_commands() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    drop(fixture.get("/ui/r/home/console/cli", &browser).await?);
    let known = text(
        fixture
            .post(
                "/ui/r/home/console/cli/check",
                &browser,
                &form(&[("line", "ip host console.example 192.0.2.10")]),
            )
            .await?,
    )
    .await?;
    assert!(
        known.contains("Catalog command: ip host"),
        "mapped: {known}"
    );
    let before = fixture.handle().request_count();
    let unknown = fixture
        .post(
            "/ui/r/home/console/cli/send",
            &browser,
            &form(&[("line", "frobnicate the router"), ("confirm", "yes")]),
        )
        .await?;
    assert_eq!(
        unknown.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown refused"
    );
    assert!(
        text(unknown)
            .await?
            .contains(&en(keys::WEB_EXPLORER_ISSUE_RAW)),
        "explains"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let escaped = text(
        fixture
            .post(
                "/ui/r/home/console/cli/check",
                &browser,
                &form(&[("line", "frobnicate the router"), ("unvalidated", "on")]),
            )
            .await?,
    )
    .await?;
    assert!(
        escaped.contains(&en(keys::WEB_CONSOLE_MATCHED_RAW)),
        "escape: {escaped}"
    );
    Ok(())
}

/// Known lines go out with parse through the change workflow; the stored lines show
/// them, and a refusal shows the router's own words.
#[tokio::test]
async fn the_cli_console_sends_lines_with_parse() -> TestResult {
    let fixture =
        Fixture::with_faults(FaultInjection::default().fail_parse_matching("refused.example", 1))
            .await?;
    let browser = fixture.login("admin").await?;
    let sent = text(
        fixture
            .post(
                "/ui/r/home/console/cli/send",
                &browser,
                &form(&[
                    ("line", "ip host console.example 192.0.2.10"),
                    ("confirm", "yes"),
                ]),
            )
            .await?,
    )
    .await?;
    assert!(
        sent.contains(&en(keys::WEB_EXPLORER_DONE_UNSAVED)),
        "sent: {sent}"
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ip host console.example 192.0.2.10"),
        "applied with parse"
    );
    let stored = text(
        fixture
            .get("/ui/r/home/explorer/stored?path=ip+host", &browser)
            .await?,
    )
    .await?;
    assert!(
        stored.contains("ip host console.example 192.0.2.10"),
        "stored lines: {stored}"
    );
    let refused = text(
        fixture
            .post(
                "/ui/r/home/console/cli/send",
                &browser,
                &form(&[
                    ("line", "ip host refused.example 192.0.2.11"),
                    ("confirm", "yes"),
                ]),
            )
            .await?,
    )
    .await?;
    assert!(
        refused.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
        "router said: {refused}"
    );
    assert!(
        refused.contains("injected parser failure."),
        "the router's words"
    );
    Ok(())
}
