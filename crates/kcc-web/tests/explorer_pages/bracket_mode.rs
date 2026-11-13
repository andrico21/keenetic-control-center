//! The recovery mechanism follows the router's reported mode; an undecidable router is refused.

use axum::http::StatusCode;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, migration, model::Profile};

use crate::{
    form, html,
    support::{Fixture, TestResult, text},
};

/// Each reported mode picks its mechanism, and a router with neither a usable mode nor a
/// fail-safe timer receives nothing.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn recovery_mechanism_follows_the_reported_mode() -> TestResult {
    let timer = Some((
        "system configuration fail-safe timer reboot 300",
        "no system configuration fail-safe timer",
    ));
    let reboot = Some(("system reboot 300", "no system reboot"));
    let rows = [
        (Some("router"), false, timer),
        (Some("extender"), false, reboot),
        (Some("bridge"), false, None),
        (None, false, timer),
        (None, true, None),
    ];
    for (mode, omit_fail_safe, expected) in rows {
        let mut scenario = migration::Fixture::default();
        scenario.mode = mode.map(str::to_owned);
        scenario.omit_fail_safe = omit_fail_safe;
        let fixture = Fixture::with_router(
            FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario),
        )
        .await?;
        let browser = fixture.login("admin").await?;
        let response = fixture
            .post(
                "/ui/r/home/console/cli/send",
                &browser,
                &form(&[("line", "ip http port 8082"), ("confirm", "yes")]),
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await?;
        let log = fixture.handle().request_log();
        let commands = log
            .iter()
            .filter_map(|record| record.command())
            .collect::<Vec<_>>();
        let label = format!("{mode:?} omit={omit_fail_safe}: {commands:?}");
        if let Some((arm, disarm)) = expected {
            assert!(
                commands.contains(&arm) && commands.contains(&disarm),
                "{label}"
            );
        } else {
            let message = html(&tr(Locale::En, keys::MANAGEMENT_MODE_UNKNOWN, None));
            assert!(body.contains(&message), "{label}: {body}");
            assert!(commands.is_empty(), "nothing is sent: {label}");
            assert!(
                !fixture.handle().running_config_text().contains("port 8082"),
                "{label}"
            );
        }
    }
    Ok(())
}
