//! The `opkg` lines the planners send and their read-back.

use kcc_app::workflow::WorkflowError;
use kcc_domain::entware::{self, models::TimezoneSetting};
use kcc_testkit::{FaultInjection, model::Firmware};

use crate::{
    Planner, apply, heard,
    support::{Fixture, PROFILES, TestResult, administrator},
};

/// Todo 4: every planner sends exactly its line, which is read back from `show rc` and
/// left unsaved.
#[tokio::test]
async fn planners_send_their_line_and_read_it_back() -> TestResult {
    let rows: [(Option<&str>, &str, Planner); 8] = [
        (None, "opkg chroot", |ctx| {
            entware::plan_chroot(ctx, "router", &administrator(), true)
        }),
        (Some("opkg chroot"), "no opkg chroot", |ctx| {
            entware::plan_chroot(ctx, "router", &administrator(), false)
        }),
        (None, "opkg dns-override", |ctx| {
            entware::plan_dns_override(ctx, "router", &administrator(), true)
        }),
        (Some("opkg dns-override"), "no opkg dns-override", |ctx| {
            entware::plan_dns_override(ctx, "router", &administrator(), false)
        }),
        (Some("opkg disk fixture-media:/"), "no opkg disk", |ctx| {
            entware::plan_remove(ctx, "router", &administrator(), true)
        }),
        (None, "opkg timezone Europe/Berlin", |ctx| {
            entware::plan_timezone(
                ctx,
                "router",
                &administrator(),
                TimezoneSetting::Named("Europe/Berlin".to_owned()),
            )
        }),
        (
            Some("opkg timezone Europe/Berlin"),
            "opkg timezone auto",
            |ctx| entware::plan_timezone(ctx, "router", &administrator(), TimezoneSetting::Auto),
        ),
        (None, "opkg initrc /opt/etc/init.d/rc.unslung", |ctx| {
            entware::plan_initrc(
                ctx,
                "router",
                &administrator(),
                "/opt/etc/init.d/rc.unslung",
                true,
            )
        }),
    ];
    for firmware in PROFILES {
        for (before, line, planner) in rows {
            let fixture = Fixture::spawn(firmware).await?;
            if let Some(setup) = before {
                assert!(fixture.handle().configure(setup), "{setup}");
            }
            let plan = planner(fixture.context())?;

            let unsaved = apply(&fixture, &plan.operation).await?;

            assert_eq!(unsaved.ok(), Some(true), "{firmware} {line}");
            assert!(heard(&fixture, line), "{firmware} {line}");
            fixture.shutdown().await?;
        }
    }
    Ok(())
}

/// Todo 4: an `opkg` line the router acknowledges but ignores fails read-back naming the
/// field of `show rc opkg` it compared.
#[tokio::test]
async fn ignored_lines_fail_read_back_naming_the_field() -> TestResult {
    let rows: [(Option<&str>, &str, &str, Planner); 8] = [
        (None, "opkg chroot", "/chroot", |ctx| {
            entware::plan_chroot(ctx, "router", &administrator(), true)
        }),
        (Some("opkg chroot"), "no opkg chroot", "/chroot", |ctx| {
            entware::plan_chroot(ctx, "router", &administrator(), false)
        }),
        (None, "opkg dns-override", "/dns-override", |ctx| {
            entware::plan_dns_override(ctx, "router", &administrator(), true)
        }),
        (
            Some("opkg dns-override"),
            "no opkg dns-override",
            "/dns-override",
            |ctx| entware::plan_dns_override(ctx, "router", &administrator(), false),
        ),
        (
            Some("opkg disk fixture-media:/"),
            "no opkg disk",
            "/disk",
            |ctx| entware::plan_remove(ctx, "router", &administrator(), true),
        ),
        (
            None,
            "opkg timezone Europe/Berlin",
            "/timezone/timezone",
            |ctx| {
                entware::plan_timezone(
                    ctx,
                    "router",
                    &administrator(),
                    TimezoneSetting::Named("Europe/Berlin".to_owned()),
                )
            },
        ),
        (None, "opkg timezone auto", "/timezone/auto", |ctx| {
            entware::plan_timezone(ctx, "router", &administrator(), TimezoneSetting::Auto)
        }),
        (
            None,
            "opkg initrc /opt/etc/init.d/rc.unslung",
            "/initrc/path",
            |ctx| {
                entware::plan_initrc(
                    ctx,
                    "router",
                    &administrator(),
                    "/opt/etc/init.d/rc.unslung",
                    true,
                )
            },
        ),
    ];
    for (before, line, field, planner) in rows {
        let fixture = Fixture::spawn_with_faults(
            Firmware::V5_1,
            FaultInjection::default().silent_noop_path(line),
        )
        .await?;
        if let Some(setup) = before {
            assert!(fixture.handle().configure(setup), "{setup}");
        }
        let plan = planner(fixture.context())?;

        let outcome = apply(&fixture, &plan.operation).await?;

        assert!(
            matches!(&outcome, Err(WorkflowError::VerificationFailed { field: failed }) if failed == field),
            "{line}: {outcome:?}"
        );
        fixture.shutdown().await?;
    }
    Ok(())
}
