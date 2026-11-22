//! The settings changes: each changes the fake router and sends the region again.
//!
//! Chroot warns before it is turned on, the startup script and the removal need the router
//! name, DNS override asks first and runs inside the fail-safe timer, and values outside
//! the domain's grammar are refused with the field's rule before anything is sent.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::bracket::Recovery;

use super::{DRIVE, PAGE, heard, heard_since, mark, over, ready};
use crate::support::{
    asked::asks_first,
    outcome::TestResult,
    page::{en, header_text, text},
    web::Fixture,
};

/// The region sent again out of band after a change.
const REGION: &str = "id=\"entware-region\" hx-swap-oob=\"true\"";

/// A router with Entware set up on the fixture drive.
async fn set_up() -> TestResult<Fixture> {
    let fixture = over(ready()).await?;
    assert!(fixture.handle().configure(&format!("opkg disk {DRIVE}")));
    Ok(fixture)
}

/// Todo 12: turning chroot on first shows the domain's warning and sends nothing; the
/// confirmed request changes the router and sends the region again; turning it off asks
/// nothing.
#[tokio::test]
async fn chroot_warns_before_it_is_turned_on() -> TestResult {
    let fixture = set_up().await?;
    let operator = fixture.login("operator").await?;
    let on = format!("{PAGE}/chroot?on=true");
    let before = mark(&fixture);
    let asked = fixture.post(&on, &operator, "").await?;
    assert_eq!(
        header_text(&asked, "hx-retarget").as_deref(),
        Some("#dialog-content")
    );
    let dialog = text(asked).await?;
    assert!(
        dialog.contains(&en(keys::WEB_SYSTEM_ENTWARE_CHROOT_WARNING)),
        "{dialog}"
    );
    assert!(
        dialog.contains("name=\"confirm\" value=\"yes\""),
        "{dialog}"
    );
    assert_eq!(
        heard_since(&fixture, before),
        Vec::<String>::new(),
        "nothing sent"
    );
    let body = text(fixture.post(&on, &operator, "confirm=yes").await?).await?;
    assert!(body.contains(REGION), "{body}");
    assert!(body.contains("id=\"entware-chroot-warning\""), "{body}");
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("opkg chroot")
    );
    assert!(fixture.audited("web.entware_chroot", "success")?);
    let off = text(
        fixture
            .post(&format!("{PAGE}/chroot?on=false"), &operator, "")
            .await?,
    )
    .await?;
    assert!(off.contains(REGION), "no dialog to turn it off: {off}");
    assert!(
        !fixture
            .handle()
            .running_config_text()
            .contains("opkg chroot")
    );
    Ok(())
}

/// Todo 12: the time zone is set and read back; a value outside the domain's grammar is
/// refused with the field's rule and never reaches the router.
#[tokio::test]
async fn the_time_zone_is_set_and_bad_values_are_refused() -> TestResult {
    let fixture = set_up().await?;
    let operator = fixture.login("operator").await?;
    let path = format!("{PAGE}/timezone");
    for (typed, line) in [
        ("Europe/Berlin", "opkg timezone Europe/Berlin"),
        ("auto", "opkg timezone auto"),
    ] {
        let body = text(
            fixture
                .post(&path, &operator, &format!("timezone={typed}"))
                .await?,
        )
        .await?;
        assert!(body.contains(REGION), "{typed}: {body}");
        assert!(heard(&fixture, line), "{line}");
    }
    let before = mark(&fixture);
    for bad in ["bad%20zone%3Breboot", "", "x%22%3E%3Cb%3E"] {
        let response = fixture
            .post(&path, &operator, &format!("timezone={bad}"))
            .await?;
        let body = text(response).await?;
        assert!(
            body.contains(&en(keys::WEB_SYSTEM_ENTWARE_TIMEZONE_RULE)),
            "{bad}: {body}"
        );
        assert!(!body.contains("\"><b>"), "escaped: {body}");
    }
    assert!(
        heard_since(&fixture, before)
            .iter()
            .all(|line| !line.contains("opkg timezone")),
        "nothing sent"
    );
    Ok(())
}

/// Todo 12: the startup script is destructive: the router name is asked for first and
/// nothing is sent until it was typed; a path outside `/opt/` is refused with the rule.
#[tokio::test]
async fn the_startup_script_needs_the_router_name() -> TestResult {
    let fixture = set_up().await?;
    let admin = fixture.login("admin").await?;
    let path = format!("{PAGE}/initrc");
    let script = "path=/opt/etc/init.d/rc.unslung";
    let before = mark(&fixture);
    let asked = text(fixture.post(&path, &admin, script).await?).await?;
    assert!(
        asked.contains(&en(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
        "{asked}"
    );
    assert!(asked.contains("name=\"confirm_name\""), "{asked}");
    assert!(
        asked.contains("initrc?path=%2Fopt%2Fetc%2Finit.d%2Frc.unslung"),
        "{asked}"
    );
    assert_eq!(
        heard_since(&fixture, before),
        Vec::<String>::new(),
        "nothing sent"
    );
    let body = text(
        fixture
            .post(
                &path,
                &admin,
                &format!("{script}&confirm=yes&confirm_name=home"),
            )
            .await?,
    )
    .await?;
    assert!(body.contains(REGION), "{body}");
    assert!(heard(&fixture, "opkg initrc /opt/etc/init.d/rc.unslung"));
    let refusing = mark(&fixture);
    let refused = text(
        fixture
            .post(
                &path,
                &admin,
                "path=/etc/passwd&confirm=yes&confirm_name=home",
            )
            .await?,
    )
    .await?;
    assert!(
        refused.contains(&en(keys::WEB_SYSTEM_ENTWARE_INITRC_RULE)),
        "{refused}"
    );
    assert!(
        heard_since(&fixture, refusing)
            .iter()
            .all(|line| !line.contains("opkg initrc")),
        "nothing sent"
    );
    Ok(())
}

/// Todo 12: DNS override asks first and runs inside the fail-safe timer.
///
/// The kit's management dialog comes before anything is read or sent; confirmed, the
/// router hears the fail-safe arm before `opkg dns-override` and the disarm after it, and
/// the region comes back with the household warning.
#[tokio::test]
async fn dns_override_asks_and_runs_inside_the_fail_safe_timer() -> TestResult {
    let fixture = set_up().await?;
    let operator = fixture.login("operator").await?;
    let on = format!("{PAGE}/dns-override?on=true");
    let before = mark(&fixture);
    let confirm = asks_first(&fixture, &operator, (&on, &[])).await?;
    assert_eq!(
        heard_since(&fixture, before),
        Vec::<String>::new(),
        "nothing sent"
    );
    assert!(confirm.ends_with("/dns-override?on=true"), "{confirm}");
    let response = fixture.post(&on, &operator, "confirm=yes").await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = text(response).await?;
    assert!(body.contains(REGION), "{body}");
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_ENTWARE_DNS_WARNING)),
        "{body}"
    );
    let sent = heard_since(&fixture, before);
    let [arm, disarm] = Recovery::for_mode("router").lines();
    let at = |wanted: &dyn Fn(&str) -> bool| sent.iter().position(|line| wanted(line));
    let armed = at(&|line| line == arm).ok_or("armed")?;
    let changed = at(&|line| line == "opkg dns-override").ok_or("changed")?;
    let disarmed = at(&|line| line == disarm).ok_or("disarmed")?;
    assert!(armed < changed && changed < disarmed, "{sent:?}");
    assert!(!fixture.handle().recovery_armed(), "the timer is off again");
    assert!(fixture.audited("web.entware_dns_override", "success")?);
    Ok(())
}

/// Todo 12: the removal asks for the router name and sends nothing before; confirmed, the
/// router forgets `opkg disk` and the region offers the setup again.
#[tokio::test]
async fn the_removal_needs_the_router_name() -> TestResult {
    let fixture = set_up().await?;
    let admin = fixture.login("admin").await?;
    let path = format!("{PAGE}/remove");
    let before = mark(&fixture);
    let asked = text(fixture.post(&path, &admin, "").await?).await?;
    assert!(
        asked.contains(&en(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
        "{asked}"
    );
    assert_eq!(
        heard_since(&fixture, before),
        Vec::<String>::new(),
        "nothing sent"
    );
    let wrong = text(
        fixture
            .post(&path, &admin, "confirm=yes&confirm_name=office")
            .await?,
    )
    .await?;
    assert!(
        wrong.contains(&en(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
        "{wrong}"
    );
    assert!(fixture.handle().running_config_text().contains("opkg disk"));
    let body = text(
        fixture
            .post(&path, &admin, "confirm=yes&confirm_name=home")
            .await?,
    )
    .await?;
    assert!(body.contains(REGION), "{body}");
    assert!(
        body.contains(&format!("hx-post=\"{PAGE}/setup\"")),
        "{body}"
    );
    assert!(heard(&fixture, "no opkg disk"));
    assert!(!fixture.handle().running_config_text().contains("opkg disk"));
    assert!(fixture.audited("web.entware_remove", "success")?);
    Ok(())
}
