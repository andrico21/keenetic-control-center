//! Raw console authorization and recovery in both router modes.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::use_debug,
    reason = "acceptance assertions establish console security"
)]

use std::io::{self, Write as _};

use axum::http::StatusCode;
use kcc_testkit::{FakeRouter, migration, model::Profile};

use crate::{
    form,
    support::{Fixture, TestResult, text},
};

/// Both consoles and positive/negative raw encodings require management protection.
fn cases() -> Vec<(&'static str, String)> {
    let mut cases = [
        "no interface Bridge0",
        "system mode EXTENDER",
        "interface Bridge0 ip access-group LabAcl in",
        "interface Bridge0 security-level public",
        "ip ssh port 2222",
        "no service http",
    ]
    .into_iter()
    .map(|line| {
        (
            "/ui/r/home/console/cli/send",
            form(&[("line", line), ("confirm", "yes"), ("confirm_name", "home")]),
        )
    })
    .collect::<Vec<_>>();
    for body in [
        r#"{"interface":{"name":"Bridge0","no":true}}"#,
        r#"{"system":{"mode":{"mode":"extender"}}}"#,
        r#"{"service":{"telnet":{}}}"#,
        r#"[{"service http":{"no":true}}]"#,
    ] {
        cases.push((
            "/ui/r/home/console/rci/send",
            form(&[
                ("method", "POST"),
                ("path", ""),
                ("body", body),
                ("confirm", "yes"),
                ("confirm_name", "home"),
            ]),
        ));
    }
    cases
}

/// Raw writers apply ordinary named-interface leaves without recovery.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn ordinary_interface_leaves_apply_without_destructive() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        for body in [
            r#"{"interface":{"name":"GigabitEthernet0/0","description":{"description":"lab"}}}"#,
            r#"[{"interface":{"name":"WifiMaster0/AccessPoint1","ssid":{"ssid":"lab"}}}]"#,
        ] {
            let fixture = Fixture::with_router(
                FakeRouter::builder(Profile::default())
                    .build()?
                    .with_migration(scenario.clone()),
            )
            .await?;
            let browser = fixture.login("raw-writer").await?;
            let before = fixture.handle().request_count();
            let response = fixture
                .post(
                    "/ui/r/home/console/rci/send",
                    &browser,
                    &form(&[("method", "POST"), ("path", ""), ("body", body)]),
                )
                .await?;
            assert_eq!(response.status(), StatusCode::OK, "{mode} {body}");
            assert!(fixture.handle().request_count() > before, "{mode} {body}");
            assert!(!fixture.handle().recovery_armed());
        }
    }
    Ok(())
}

/// The console chooses the fail-safe explanation for newly classified management commands.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn raw_management_dialog_uses_recovery_wording() -> TestResult {
    let fixture = Fixture::new().await?;
    let browser = fixture.login("admin").await?;
    for line in ["no interface Bridge0", "system mode EXTENDER"] {
        let response = fixture
            .post(
                "/ui/r/home/console/cli/send",
                &browser,
                &form(&[("line", line)]),
            )
            .await?;
        let page = text(response).await?;
        assert!(
            page.contains("data-message-key=\"web-explorer-confirm-management-text\""),
            "{line}: {page}"
        );
        assert!(
            !page.contains("data-message-key=\"web-explorer-confirm-destructive-text\""),
            "{line}: {page}"
        );
    }
    Ok(())
}

/// A role without Destructive cannot mutate management settings or arm recovery.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn raw_management_permission_refuses_both_modes() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fixture = Fixture::with_router(
            FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario),
        )
        .await?;
        let browser = fixture.login("raw-writer").await?;
        drop(fixture.get("/ui/r/home/console/rci", &browser).await?);
        let before = fixture.handle().request_count();
        let mut inputs = cases();
        inputs.push((
            "/ui/r/home/console/cli/send",
            form(&[
                ("line", "system configuration fail-safe timer reboot 300"),
                ("confirm", "yes"),
                ("confirm_name", "home"),
            ]),
        ));
        inputs.push((
            "/ui/r/home/console/cli/send",
            form(&[
                ("line", "interface WifiMaster0/AccessPoint0 schedule sample"),
                ("confirm", "yes"),
                ("confirm_name", "home"),
            ]),
        ));
        inputs.push((
            "/ui/r/home/console/rci/send",
            form(&[
                ("method", "POST"),
                ("path", ""),
                (
                    "body",
                    r#"{"interface":{"name":"WifiMaster0/AccessPoint0","schedule":{"schedule":"sample"}}}"#,
                ),
                ("confirm", "yes"),
                ("confirm_name", "home"),
            ]),
        ));
        for (endpoint, request) in inputs {
            let response = fixture.post(endpoint, &browser, &request).await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{request}");
            assert_eq!(
                fixture.handle().request_count(),
                before,
                "no requests: {request}"
            );
            writeln!(
                io::stderr(),
                "RAW Web raw-writer {mode} {endpoint} {request}: 403, zero requests"
            )?;
        }
    }
    Ok(())
}

/// Confirmed administrators get the recovery mechanism selected by router mode.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn raw_management_brackets_both_modes() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let fixture = Fixture::with_router(
            FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(scenario),
        )
        .await?;
        let browser = fixture.login("admin").await?;
        for (endpoint, request) in cases() {
            let before = fixture.handle().request_log().len();
            let response = fixture.post(endpoint, &browser, &request).await?;
            assert_eq!(response.status(), StatusCode::OK, "{request}");
            let commands = fixture
                .handle()
                .request_log()
                .iter()
                .skip(before)
                .filter_map(|record| record.command().map(str::to_owned))
                .collect::<Vec<_>>();
            let (arm, disarm) = if mode == "router" {
                (
                    "system configuration fail-safe timer reboot 300",
                    "no system configuration fail-safe timer",
                )
            } else {
                ("system reboot 300", "no system reboot")
            };
            assert_eq!(
                commands.first().map(String::as_str),
                Some(arm),
                "{request}: {commands:?}"
            );
            assert_eq!(
                commands.last().map(String::as_str),
                Some(disarm),
                "{request}: {commands:?}"
            );
            assert!(!fixture.handle().recovery_armed(), "successful cleanup");
            writeln!(
                io::stderr(),
                "RAW Web admin {mode} {endpoint} {request}: {commands:?}"
            )?;
        }
    }
    Ok(())
}
