//! KeenDNS.
//!
//! Per-role controls, the name released through the change workflow, a name refused
//! before anything is sent, and the management changes: the remote access level the fake
//! refuses and a web proxy entry, both inside the fail-safe timer.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    audited, cli_targets, en, form,
    support::{Fixture, TestResult, header_text, text},
};

/// The page under test.
const PAGE: &str = "/ui/r/home/system/keendns";

#[tokio::test]
async fn each_role_sees_the_name_and_only_its_controls() -> TestResult {
    let fixture = Fixture::new().await?;
    let release = "hx-post=\"/ui/r/home/system/keendns/drop\"";
    let access = "hx-post=\"/ui/r/home/system/keendns/access?level=private\"";
    let proxy = "hx-get=\"/ui/r/home/system/keendns/proxy\"";
    for (account, releases, manages) in [
        ("viewer", false, false),
        ("operator", true, true),
        ("admin", true, true),
    ] {
        let browser = fixture.login(account).await?;
        let page = text(fixture.get(PAGE, &browser).await?).await?;
        for shown in ["router.fixture.invalid", "registered"] {
            assert!(page.contains(shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(release), releases, "{account} release");
        assert_eq!(page.contains(access), manages, "{account} access");
        assert_eq!(page.contains(proxy), manages, "{account} proxy");
    }
    let viewer = fixture.login("viewer").await?;
    let denied = fixture
        .post(&format!("{PAGE}/access?level=private"), &viewer, "")
        .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN, "management");
    Ok(())
}

#[tokio::test]
async fn the_name_is_released_and_a_bad_name_is_refused() -> TestResult {
    let fixture = Fixture::new().await?;
    let operator = fixture.login("operator").await?;
    let released = text(fixture.post(&format!("{PAGE}/drop"), &operator, "").await?).await?;
    assert!(released.contains("data-tone=\"success\""), "{released}");
    assert!(
        released.contains("id=\"keendns-status\""),
        "the panel read back"
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("drop-name router fixture.invalid"),
        "the router has it: {}",
        fixture.handle().running_config_text()
    );
    let before = fixture.handle().running_config_text();
    let refused = fixture
        .post(
            &format!("{PAGE}/book"),
            &operator,
            &form(&[("name", "my office"), ("domain", "keenetic.pro")]),
        )
        .await?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY, "422");
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_SYSTEM_KEENDNS_NAME_ERROR)),
        "the rule"
    );
    assert_eq!(
        fixture.handle().running_config_text(),
        before,
        "nothing sent"
    );
    assert!(audited(&fixture, "web.keendns_drop", "success")?, "audited");
    Ok(())
}

#[tokio::test]
async fn management_changes_ask_first_and_run_inside_the_fail_safe_timer() -> TestResult {
    let fixture = Fixture::with_faults(
        kcc_testkit::FaultInjection::default()
            .fail_parse_matching("cloud control2 security-level", 1),
    )
    .await?;
    let admin = fixture.login("admin").await?;
    let access = format!("{PAGE}/access?level=private");
    let asked = fixture.post(&access, &admin, "").await?;
    assert_eq!(
        header_text(&asked, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "dialog"
    );
    assert!(
        text(asked)
            .await?
            .contains(&en(keys::WEB_KIT_CONFIRM_MANAGEMENT_TITLE)),
        "explains the timer"
    );
    let refused = text(fixture.post(&access, &admin, "confirm=yes").await?).await?;
    assert!(refused.contains(&en(keys::WEB_KIT_REJECTED)), "{refused}");
    assert!(
        refused.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
        "router said"
    );
    let fields = [
        ("name", "nas"),
        ("protocol", "http"),
        ("host", "192.0.2.40"),
        ("port", "5000"),
        ("confirm", "yes"),
    ];
    let published = text(
        fixture
            .post(&format!("{PAGE}/proxy"), &admin, &form(&fields))
            .await?,
    )
    .await?;
    assert!(
        published.contains(&en(keys::WEB_KIT_DONE_UNSAVED)),
        "{published}"
    );
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("ip http proxy nas"),
        "the router has it"
    );
    let fail_safe = cli_targets(&fixture)?
        .into_iter()
        .filter(|target| target == "system configuration fail-safe timer")
        .count();
    assert_eq!(fail_safe, 4, "armed and disarmed around both changes");
    assert!(
        audited(&fixture, "web.keendns_access", "rci_error")?
            && audited(&fixture, "web.keendns_proxy", "success")?,
        "audited"
    );
    Ok(())
}
