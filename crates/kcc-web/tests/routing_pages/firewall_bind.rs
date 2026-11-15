//! The firewall's interfaces: lists applied and taken off, read back from the router.
//!
//! A list applied to an uplink is a plain change; applying one to the interface kcc reaches
//! the router through asks first, needs `Destructive` and runs inside the fail-safe timer.
//! A 4.3.9 router without IPv6 access lists gets the explorer note.

use core::net::SocketAddr;

use axum::http::StatusCode;
use kcc_app::{permissions::built_in_roles, registry::ManagedRouterProfile};
use kcc_i18n::keys;
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, migration,
    model::{Firmware, Model, Profile},
};
use tempfile::TempDir;
use url::Url;

use crate::{
    firewall::two_rules,
    get, post,
    support::{outcome::TestResult, page::en, web::Fixture},
};

/// The catalog path of the fail-safe timer's arm and disarm lines.
const TIMER: &str = "system configuration fail-safe timer";

/// Runtime management bindings keep the Web's confirmation and recovery in both modes.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test]
async fn management_firewall_binding_brackets_both_modes() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fake = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::with_router(fake).await?;
        let admin = fixture.login("admin").await?;
        two_rules(&fixture, &admin).await?;
        let (arm, disarm) = if mode == "router" {
            (
                "system configuration fail-safe timer reboot 300",
                "no system configuration fail-safe timer",
            )
        } else {
            ("system reboot 300", "no system reboot")
        };
        for path in [
            "/ui/r/home/firewall/bind?list=WebAcl&interface=Bridge0&direction=in",
            "/ui/r/home/firewall/rule/new?list=WebAcl&action=deny&protocol=ip&source=192.0.2.5&source_mask=255.255.255.255&destination=198.51.100.5&destination_mask=255.255.255.255",
            "/ui/r/home/firewall/unbind?interface=Bridge0&list=WebAcl&direction=in",
        ] {
            let asked = post(&fixture, &admin, (path, &[]), StatusCode::OK).await?;
            assert!(
                asked.contains(&en(keys::WEB_KIT_CONFIRM_MANAGEMENT_TITLE)),
                "dialog"
            );
            for role in ["operator", "writer"] {
                let browser = fixture.login(role).await?;
                let before = fixture.handle().request_log().len();
                drop(
                    post(
                        &fixture,
                        &browser,
                        (path, &[("confirm", "yes")]),
                        StatusCode::FORBIDDEN,
                    )
                    .await?,
                );
                assert!(
                    fixture
                        .handle()
                        .request_log()
                        .iter()
                        .skip(before)
                        .all(|record| record.command().is_none()),
                    "no unauthorized mutation"
                );
            }
            let before = fixture.handle().request_log().len();
            drop(
                post(
                    &fixture,
                    &admin,
                    (path, &[("confirm", "yes")]),
                    StatusCode::OK,
                )
                .await?,
            );
            let commands = fixture
                .handle()
                .request_log()
                .iter()
                .skip(before)
                .filter_map(|record| record.command().map(str::to_owned))
                .collect::<Vec<_>>();
            assert_eq!(
                commands.first().map(String::as_str),
                Some(arm),
                "{mode} {path}: {commands:?}"
            );
            assert_eq!(
                commands.last().map(String::as_str),
                Some(disarm),
                "{mode} {path}: {commands:?}"
            );
        }
        assert_eq!(applied(&fixture), 0, "last action unbound the list");
    }
    Ok(())
}

/// Applying `WebAcl` inbound to `interface`, confirmed when `confirm` is set.
fn binding(interface: &str, confirm: bool) -> Vec<(&str, &str)> {
    let mut fields = vec![
        ("list", "WebAcl"),
        ("interface", interface),
        ("direction", "in"),
    ];
    if confirm {
        fields.push(("confirm", "yes"));
    }
    fields
}

/// How often the router's running configuration applies a list to an interface.
fn applied(fixture: &Fixture) -> usize {
    fixture
        .handle()
        .running_config_text()
        .matches("ip access-group WebAcl in")
        .count()
}

#[tokio::test]
async fn a_list_is_applied_to_an_uplink_and_taken_off_with_read_back() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    two_rules(&fixture, &admin).await?;
    let bind = "/ui/r/home/firewall/bind";
    let bound = post(
        &fixture,
        &admin,
        (bind, &binding("ISP", false)),
        StatusCode::OK,
    )
    .await?;
    assert!(
        bound.contains(&en(keys::WEB_KIT_DONE_UNSAVED)),
        "a plain write: {bound}"
    );
    assert_eq!(applied(&fixture), 1, "applied");
    let page = "/ui/r/home/firewall/interfaces";
    let interfaces = get(&fixture, &admin, page, StatusCode::OK).await?;
    assert!(
        interfaces.contains("ISP") && interfaces.contains("WebAcl"),
        "{interfaces}"
    );
    let operator = fixture.login("operator").await?;
    let unbind = "/ui/r/home/firewall/unbind?interface=ISP&list=WebAcl&direction=in";
    drop(post(&fixture, &operator, (unbind, &[]), StatusCode::OK).await?);
    assert_eq!(applied(&fixture), 0, "taken off");
    assert!(
        fixture.audited("web.firewall_unbind", "success")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn applying_a_list_to_kcc_s_own_interface_asks_and_runs_in_the_fail_safe_timer() -> TestResult
{
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    two_rules(&fixture, &admin).await?;
    let bind = "/ui/r/home/firewall/bind";
    let asked = post(
        &fixture,
        &admin,
        (bind, &binding("Bridge0", false)),
        StatusCode::OK,
    )
    .await?;
    let title = en(keys::WEB_KIT_CONFIRM_MANAGEMENT_TITLE);
    assert!(asked.contains(&title), "asks first: {asked}");
    assert!(
        asked.contains("name=\"confirm\" value=\"yes\""),
        "the confirmation"
    );
    assert_eq!(applied(&fixture), 0, "nothing sent yet");
    let operator = fixture.login("operator").await?;
    let confirmed = binding("Bridge0", true);
    drop(
        post(
            &fixture,
            &operator,
            (bind, &confirmed),
            StatusCode::FORBIDDEN,
        )
        .await?,
    );
    let done = post(&fixture, &admin, (bind, &confirmed), StatusCode::OK).await?;
    assert!(done.contains(&en(keys::WEB_KIT_DONE_UNSAVED)), "{done}");
    assert_eq!(applied(&fixture), 1, "applied to Bridge0");
    let timer = fixture
        .audit()?
        .into_iter()
        .filter(|entry| entry.action == "router.change_cli")
        .filter(|entry| entry.target.as_deref() == Some(TIMER))
        .count();
    assert_eq!(timer, 2, "the fail-safe timer armed and disarmed");
    let unbind = "/ui/r/home/firewall/unbind?interface=Bridge0&list=WebAcl&direction=in";
    let yes = [("confirm", "yes")];
    drop(post(&fixture, &operator, (unbind, &yes), StatusCode::FORBIDDEN).await?);
    assert_eq!(applied(&fixture), 1, "kept");
    Ok(())
}

#[tokio::test]
async fn a_4_3_9_router_without_ipv6_lists_gets_the_explorer_note() -> TestResult {
    let fixture = Fixture::new().await?;
    let (address, handle) = FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V4_3)?)
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let directory = TempDir::new()?;
    let password_file =
        kcc_testkit::write_secret_file(directory.path(), "password", DEFAULT_PASSWORD)?;
    let admin_role = built_in_roles()
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or("admin role")?;
    let url = Url::parse(&format!("http://{address}"))?;
    let profile = ManagedRouterProfile::new(
        "legacy".to_owned(),
        url,
        DEFAULT_LOGIN.to_owned(),
        password_file,
    );
    fixture.registry().create(&admin_role, profile).await?;
    let viewer = fixture.login("viewer").await?;
    let page = get(&fixture, &viewer, "/ui/r/legacy/firewall", StatusCode::OK).await?;
    assert!(
        page.contains(&en(keys::WEB_FIREWALL_IPV6_MISSING)),
        "the note: {page}"
    );
    assert!(
        page.contains("href=\"/ui/r/legacy/explorer\""),
        "the explorer link"
    );
    assert!(
        !page.contains(&en(keys::WEB_FIREWALL_IPV6_READONLY)),
        "no IPv6 lists"
    );
    assert!(
        !page.contains(&en(keys::WEB_FIREWALL_ADD)),
        "a viewer adds nothing"
    );
    handle.shutdown().await?;
    Ok(())
}
