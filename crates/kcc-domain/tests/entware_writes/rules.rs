//! The planners' grammar, risk classes, permissions, confirmations and warnings.

use kcc_app::permissions::{Permission, Role};
use kcc_catalog::Risk;
use kcc_domain::{
    DomainError,
    dns::{self, DnsChange},
    entware::{
        self,
        models::{EntwarePlan, EntwareWarning, TimezoneSetting},
    },
};
use kcc_testkit::model::Firmware;

use crate::{
    operator,
    support::{Fixture, PROFILES, TestResult, administrator},
    viewer,
};

/// Todo 4: timezone names and init script paths outside their grammar are refused before
/// any router request; the edges of the grammar and real zone names are accepted.
///
/// A zone name containing `..` or `//` (a URL), starting with anything but a letter, a
/// digit or `<`, or spelling `auto` in any case is refused.
#[tokio::test]
async fn timezone_and_initrc_grammar_is_checked_before_any_request() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    let ctx = fixture.context();
    let role = administrator();
    let before = fixture.handle().request_log().len();
    let longest_zone = "Z".repeat(64);
    let longest_path = format!("/opt/{}", "p".repeat(200));
    for zone in [
        "UTC+3",
        "<+03>-3",
        "GMT-1,M3.5.0/2:00",
        "Etc/GMT_x.y",
        "Europe/Berlin",
        "Asia/Almaty",
        "UTC",
        "Etc/GMT+3",
        "America/Port-au-Prince",
        "EST5EDT",
        "GMT-0",
        longest_zone.as_str(),
    ] {
        drop(
            entware::plan_timezone(
                ctx,
                "router",
                &role,
                TimezoneSetting::Named(zone.to_owned()),
            )
            .map_err(|error| format!("{zone}: {error}"))?,
        );
    }
    let too_long_zone = "Z".repeat(65);
    for zone in [
        "",
        "Europe/Ber lin",
        "a;b",
        "a|b",
        "Zone\"x",
        "Zone'x",
        "a\\b",
        "Zone=x",
        "auto",
        "AUTO",
        "Auto",
        "..",
        "a..b",
        "-x",
        "-",
        "https://evil.example/tz",
        "a//b",
        too_long_zone.as_str(),
    ] {
        let planned = entware::plan_timezone(
            ctx,
            "router",
            &role,
            TimezoneSetting::Named(zone.to_owned()),
        );
        assert!(
            matches!(planned, Err(DomainError::InvalidCliToken)),
            "{zone:?}: {planned:?}"
        );
    }
    for path in [
        "/opt/etc/init.d/rc.unslung",
        "/opt/a-b_c.d/e",
        longest_path.as_str(),
    ] {
        drop(
            entware::plan_initrc(ctx, "router", &role, path, true)
                .map_err(|error| format!("{path}: {error}"))?,
        );
    }
    let too_long_path = format!("/opt/{}", "p".repeat(201));
    for path in [
        "/etc/init.d/rc.unslung",
        "/opt/",
        "/opt",
        "opt/x",
        "/opt/../etc/passwd",
        "/opt/a..b",
        "/opt/a b",
        "/opt/x;reboot",
        "/opt/x|y",
        "/opt/x$y",
        too_long_path.as_str(),
    ] {
        let planned = entware::plan_initrc(ctx, "router", &role, path, true);
        assert!(
            matches!(planned, Err(DomainError::InvalidCliToken)),
            "{path:?}: {planned:?}"
        );
    }
    assert_eq!(fixture.handle().request_log().len(), before);
    fixture.shutdown().await?;
    Ok(())
}

/// Todo 4: the plans carry their risk class, the permission they need and their warnings.
///
/// Only `opkg` plans convert into an Entware request. Enabling chroot warns that SSH
/// management stops working, and enabling the DNS override warns that the router's DNS
/// stops serving the household.
#[tokio::test]
async fn plans_carry_risk_permission_and_warnings() -> TestResult {
    for firmware in PROFILES {
        let fixture = Fixture::spawn(firmware).await?;
        let ctx = fixture.context();
        let role = administrator();
        let dns = dns::plan_change(ctx, &DnsChange::Intercept { enabled: true })?;
        assert_eq!(dns.commands.len(), 1);
        assert!(matches!(
            entware::change_request(&dns),
            Err(DomainError::InvalidResponse)
        ));
        let rows: [(EntwarePlan, Risk, Permission, &[EntwareWarning]); 5] = [
            (
                entware::plan_chroot(ctx, "router", &role, true)?,
                Risk::Write,
                Permission::Write,
                &[EntwareWarning::ChrootStopsSshManagement],
            ),
            (
                entware::plan_chroot(ctx, "router", &role, false)?,
                Risk::Write,
                Permission::Write,
                &[],
            ),
            (
                entware::plan_dns_override(ctx, "router", &role, true)?,
                Risk::Management,
                Permission::Write,
                &[EntwareWarning::DnsOverrideStopsRouterDns],
            ),
            (
                entware::plan_dns_override(ctx, "router", &role, false)?,
                Risk::Management,
                Permission::Write,
                &[],
            ),
            (
                entware::plan_remove(ctx, "router", &role, true)?,
                Risk::Destructive,
                Permission::Destructive,
                &[],
            ),
        ];
        for (index, (plan, risk, permission, warnings)) in rows.into_iter().enumerate() {
            assert_eq!(plan.operation.risk, risk, "{firmware} row {index}");
            assert_eq!(
                plan.operation.permission, permission,
                "{firmware} row {index}"
            );
            assert_eq!(
                entware::change_request(&plan.operation)?.permission,
                permission,
                "{firmware} row {index}"
            );
            assert_eq!(plan.warnings, warnings, "{firmware} row {index}");
        }
        {
            let timezone = entware::plan_timezone(ctx, "router", &role, TimezoneSetting::Auto)?;
            assert_eq!(
                (timezone.operation.risk, timezone.operation.permission),
                (Risk::Write, Permission::Write)
            );
            let initrc =
                entware::plan_initrc(ctx, "router", &role, "/opt/etc/init.d/rc.unslung", true)?;
            assert_eq!(
                (initrc.operation.risk, initrc.operation.permission),
                (Risk::Destructive, Permission::Destructive)
            );
        }
        fixture.shutdown().await?;
    }
    Ok(())
}

/// Todo 4: `opkg initrc` and `no opkg disk` need an explicit confirmation and the
/// `Destructive` permission; the other settings need `Write` on the router.
#[tokio::test]
async fn planners_refuse_missing_confirmation_and_permission() -> TestResult {
    let fixture = Fixture::spawn(Firmware::V5_1).await?;
    let ctx = fixture.context();
    let (admin, operator, viewer) = (administrator(), operator(), viewer());
    let elsewhere = Role::new(
        "elsewhere".to_owned(),
        Permission::ALL,
        vec!["other".to_owned()],
    );
    let path = "/opt/etc/init.d/rc.unslung";
    assert!(matches!(
        entware::plan_initrc(ctx, "router", &admin, path, false),
        Err(DomainError::ConfirmationRequired)
    ));
    assert!(matches!(
        entware::plan_remove(ctx, "router", &admin, false),
        Err(DomainError::ConfirmationRequired)
    ));
    for role in [&operator, &viewer, &elsewhere] {
        assert!(
            matches!(
                entware::plan_initrc(ctx, "router", role, path, true),
                Err(DomainError::PermissionDenied)
            ),
            "{}",
            role.name
        );
        assert!(
            matches!(
                entware::plan_remove(ctx, "router", role, true),
                Err(DomainError::PermissionDenied)
            ),
            "{}",
            role.name
        );
    }
    for role in [&viewer, &elsewhere] {
        assert!(
            matches!(
                entware::plan_chroot(ctx, "router", role, true),
                Err(DomainError::PermissionDenied)
            ),
            "{}",
            role.name
        );
        assert!(
            matches!(
                entware::plan_dns_override(ctx, "router", role, true),
                Err(DomainError::PermissionDenied)
            ),
            "{}",
            role.name
        );
        assert!(
            matches!(
                entware::plan_timezone(ctx, "router", role, TimezoneSetting::Auto),
                Err(DomainError::PermissionDenied)
            ),
            "{}",
            role.name
        );
    }
    drop(entware::plan_chroot(ctx, "router", &operator, true)?);
    drop(entware::plan_dns_override(ctx, "router", &operator, true)?);
    drop(entware::plan_timezone(
        ctx,
        "router",
        &operator,
        TimezoneSetting::Auto,
    )?);
    fixture.shutdown().await?;
    Ok(())
}
