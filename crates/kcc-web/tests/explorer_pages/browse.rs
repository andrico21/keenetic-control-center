//! Browsing: per-role controls, catalog facts and the generated form, previews and the
//! router's stored lines.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    en, form, html,
    support::{Fixture, ROUTER, TestResult, text},
};

/// Viewers and operators browse the explorer read-only; only administrators get the
/// consoles, the landing page and the Execute button of a change.
#[tokio::test]
async fn each_role_sees_only_what_it_may_run() -> TestResult {
    let fixture = Fixture::new().await?;
    for (role, admin) in [("viewer", false), ("operator", false), ("admin", true)] {
        let browser = fixture.login(role).await?;
        let page = fixture.get("/ui/r/home/explorer", &browser).await?;
        assert_eq!(page.status(), StatusCode::OK, "{role}: explorer");
        let body = text(page).await?;
        assert!(body.contains("id=\"explorer-q\""), "{role}: search box");
        assert!(
            body.contains("<span class=\"mono\">ip</span>"),
            "{role}: group tree"
        );
        assert_eq!(
            body.contains("href=\"/ui/r/home/console/rci\""),
            admin,
            "{role}: console links"
        );
        for console in [
            "/ui/r/home/console/rci",
            "/ui/r/home/console/cli",
            "/ui/advanced",
        ] {
            let status = fixture.get(console, &browser).await?.status();
            let expected = if admin {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            };
            assert_eq!(status, expected, "{role}: {console}");
        }
        let change = text(
            fixture
                .get("/ui/r/home/explorer/command?path=ip+hotspot+host", &browser)
                .await?,
        )
        .await?;
        assert_eq!(
            change.contains("type=\"submit\""),
            admin,
            "{role}: execute a change"
        );
        assert!(change.contains("explorer/preview"), "{role}: preview");
        let read = text(
            fixture
                .get("/ui/r/home/explorer/command?path=show+version", &browser)
                .await?,
        )
        .await?;
        assert!(read.contains("type=\"submit\""), "{role}: run a read");
        let denied = fixture
            .post(
                "/ui/r/home/explorer/execute",
                &browser,
                &form(&[
                    ("path", "ip hotspot host"),
                    ("a.mac", "02:00:00:00:00:91"),
                    ("confirm", "yes"),
                ]),
            )
            .await?;
        let expected = if admin {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(
            denied.status(),
            expected,
            "{role}: change via a crafted request"
        );
    }
    Ok(())
}

/// Search, the group tree and the detail show what the catalog and the official manual
/// say, and the form is generated from the command's schema.
#[tokio::test]
async fn the_detail_shows_catalog_facts_and_a_generated_form() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("viewer").await?;
    let found = text(
        fixture
            .get("/ui/r/home/explorer/search?q=hotspot+host", &browser)
            .await?,
    )
    .await?;
    assert!(
        found.contains(">ip hotspot host</span>"),
        "search result: {found}"
    );
    assert!(
        found.contains("hx-push-url=\"/ui/r/home/explorer?path=ip+hotspot+host\""),
        "bookmarkable"
    );
    let group = text(
        fixture
            .get("/ui/r/home/explorer/group?prefix=ip&page=2", &browser)
            .await?,
    )
    .await?;
    assert!(group.contains("Page 2 of"), "paged group: {group}");
    assert!(
        group.matches("class=\"command-link\"").count() <= 50,
        "50 rows per page"
    );
    let page = text(
        fixture
            .get("/ui/r/home/explorer?path=ip+hotspot+host", &browser)
            .await?,
    )
    .await?;
    for expected in [
        "<h2 class=\"command__title\" id=\"command-title\">ip hotspot host</h2>".to_owned(),
        en(keys::WEB_EXPLORER_KIND_SETTING),
        en(keys::WEB_EXPLORER_RISK_WRITE),
        "cli_manual_kn-1011.pdf#page=".to_owned(),
        "cli_manual_kn-1811.pdf".to_owned(),
        "deny, permit".to_owned(),
        "<select class=\"field__input\" id=\"arg-access\" name=\"a.access\"".to_owned(),
        "name=\"a.mac\" type=\"text\"".to_owned(),
        "type=\"checkbox\" id=\"arg-permit\" name=\"a.permit\" value=\"true\"".to_owned(),
        "type=\"checkbox\" id=\"arg-no\" name=\"a.no\" value=\"true\"".to_owned(),
        "<summary class=\"subcommand__summary\">priority</summary>".to_owned(),
        "name=\"a.priority.priority\"".to_owned(),
    ] {
        assert!(page.contains(&expected), "missing {expected}");
    }
    let unknown = text(
        fixture
            .get("/ui/r/home/explorer/command?path=no+such", &browser)
            .await?,
    )
    .await?;
    assert!(
        unknown.contains(&en(keys::WEB_EXPLORER_UNKNOWN_COMMAND)),
        "unknown command"
    );
    Ok(())
}

/// The preview shows the exact method, endpoint and JSON, masks secrets and sends
/// nothing to the router.
#[tokio::test]
async fn the_preview_is_exact_masks_secrets_and_sends_nothing() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    drop(fixture.get("/ui/r/home/explorer", &browser).await?);
    let before = fixture.handle().request_count();
    let change = text(
        fixture
            .post(
                "/ui/r/home/explorer/preview",
                &browser,
                &form(&[
                    ("path", "ip hotspot host"),
                    ("a.mac", "02:00:00:00:00:99"),
                    ("a.permit", "true"),
                ]),
            )
            .await?,
    )
    .await?;
    assert!(
        change.contains("<dd class=\"mono\">POST</dd>"),
        "method: {change}"
    );
    assert!(change.contains("<dd class=\"mono\">/rci/</dd>"), "endpoint");
    assert!(change.contains(&html("\"permit\": true")), "batch body");
    let secret = "hunter2-secret";
    let masked = text(
        fixture
            .post(
                "/ui/r/home/explorer/preview",
                &browser,
                &form(&[("path", "crypto ike key"), ("a.psk", secret)]),
            )
            .await?,
    )
    .await?;
    assert!(!masked.contains(secret), "the secret is never shown");
    assert!(
        masked.contains(&html("\"psk\": \"********\"")),
        "masked: {masked}"
    );
    assert_eq!(
        fixture.handle().request_count(),
        before,
        "a preview sends nothing"
    );
    Ok(())
}

/// The running-configuration lines of a command never show secrets.
#[tokio::test]
async fn stored_lines_redact_secrets() -> TestResult {
    let fixture = Fixture::new().await?;
    let client = fixture.registry().client(ROUTER).await?;
    drop(
        client
            .parse("interface WifiMaster0/AccessPoint0 authentication wpa-psk explorer-secret-psk")
            .await?,
    );
    let browser = fixture.login("viewer").await?;
    let stored = text(
        fixture
            .get(
                "/ui/r/home/explorer/stored?path=interface+authentication+wpa-psk",
                &browser,
            )
            .await?,
    )
    .await?;
    assert!(
        stored.contains("authentication wpa-psk"),
        "the line: {stored}"
    );
    assert!(!stored.contains("explorer-secret-psk"), "no plaintext");
    assert!(stored.contains(&html("<redacted>")), "redacted");
    let running = fixture.handle().running_config_text();
    let blob = running
        .split_once("wpa-psk ns3 ")
        .and_then(|(_, tail)| tail.split_whitespace().next())
        .ok_or("no ns3 blob in the running configuration")?;
    assert!(
        !stored.contains(blob),
        "the encoded secret is not shown either"
    );
    Ok(())
}
