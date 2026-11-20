//! Who may open the scheduled actions page, what it shows, and its requests' protection.

use axum::http::{StatusCode, header};
use kcc_app::schedules::model::{
    Action,
    names::{ClientMac, PolicyName},
};
use kcc_i18n::keys;

use crate::{
    fixture::{PAGE, Scheduled},
    stub::Stub,
    support::{
        outcome::TestResult,
        page::{en, header_text},
    },
};

/// Regression (todo 15): the page renders for an administrator and for a role holding
/// `ManageSchedules`; an operator, a viewer or a role without it gets 403 for the page and
/// its changes.
#[tokio::test]
async fn the_page_renders_only_for_roles_that_manage_schedules() -> TestResult {
    let fixture = Scheduled::build(Some(Stub::new())).await?;
    for allowed in ["admin", "sam"] {
        let browser = fixture.login(allowed).await?;
        let html = fixture.html(PAGE, &browser).await?;
        assert!(
            html.contains(&en(keys::WEB_ADMIN_SCHEDULED_EMPTY)),
            "{allowed} sees the empty table"
        );
    }
    for refused in ["operator", "viewer", "una"] {
        let browser = fixture.login(refused).await?;
        let page = fixture.get(PAGE, &browser).await?;
        assert_eq!(page.status(), StatusCode::FORBIDDEN, "{refused} page");
        let change = fixture
            .post(PAGE, &browser, &[("name", "x"), ("router", "home")])
            .await?;
        assert_eq!(change.status(), StatusCode::FORBIDDEN, "{refused} change");
    }
    assert!(fixture.schedules()?.is_empty(), "nothing was stored");
    Ok(())
}

/// Regression (todo 15): the administration tab bar links the page only for a role that
/// may open it, and a role whose only administration page it is lands on it.
#[tokio::test]
async fn the_tab_shows_only_with_the_permission() -> TestResult {
    let fixture = Scheduled::build(None).await?;
    let link = format!("href=\"{PAGE}\"");
    let admin = fixture.login("admin").await?;
    assert!(
        fixture
            .html("/ui/admin/users", &admin)
            .await?
            .contains(&link),
        "the administrator's tab bar"
    );
    let una = fixture.login("una").await?;
    assert!(
        !fixture.html("/ui/admin/users", &una).await?.contains(&link),
        "no tab without ManageSchedules"
    );
    let sam = fixture.login("sam").await?;
    let landing = fixture.get("/ui/admin", &sam).await?;
    assert_eq!(
        header_text(&landing, header::LOCATION.as_str()).as_deref(),
        Some(PAGE),
        "the only administration page sam may open"
    );
    Ok(())
}

/// Regression (todo 15): a change without the CSRF token is refused and stores nothing,
/// while the same change with it is stored.
#[tokio::test]
async fn a_change_without_csrf_is_refused() -> TestResult {
    let fixture = Scheduled::build(Some(Stub::new())).await?;
    let admin = fixture.login("admin").await?;
    let schedule = fixture.stored("Nightly backup", Action::Backup)?;
    let pause = [("id", schedule.id.as_str())];
    let tokenless = fixture
        .post_without_csrf("/ui/admin/scheduled/pause", &admin, &pause)
        .await?;
    assert_eq!(tokenless.status(), StatusCode::FORBIDDEN, "no token");
    assert_eq!(
        fixture.schedules()?.first().map(|stored| stored.state),
        Some(schedule.state),
        "still active"
    );
    let paused = fixture
        .post("/ui/admin/scheduled/pause", &admin, &pause)
        .await?;
    assert_eq!(paused.status(), StatusCode::OK, "with the token");
    assert_ne!(
        fixture.schedules()?.first().map(|stored| stored.state),
        Some(schedule.state),
        "paused"
    );
    Ok(())
}

/// Regression (todo 15): no inline script or style, and no MAC outside the client select.
///
/// The dialog suggests the bundled zones and names clients by MAC only inside the client
/// select, and the table never shows a client's MAC.
#[tokio::test]
async fn the_page_has_no_inline_code_and_no_mac_outside_the_select() -> TestResult {
    let fixture = Scheduled::build(Some(Stub::new())).await?;
    let admin = fixture.login("admin").await?;
    let mac = "02:00:00:00:10:01";
    let action = Action::PolicySwitch {
        mac: ClientMac::parse(mac)?,
        policy: PolicyName::parse("Policy0")?,
    };
    drop(fixture.stored("Kids offline", action)?);
    let page = fixture.html(PAGE, &admin).await?;
    let dialog = fixture
        .html(
            "/ui/admin/scheduled/new?router=home&kind=policy_switch&name=x",
            &admin,
        )
        .await?;
    for html in [&page, &dialog] {
        assert!(
            !html.contains("<script>") && !html.contains(" style="),
            "no inline script or style"
        );
    }
    assert!(!page.contains(mac), "no MAC in the table");
    assert!(
        dialog.contains("<datalist id=\"scheduled-zones\">")
            && dialog.contains("<option value=\"Europe/Berlin\">"),
        "the zone suggestions"
    );
    let (before, select) = dialog
        .split_once("name=\"mac\"")
        .ok_or("no client select")?;
    let (options, after) = select.split_once("</select>").ok_or("open select")?;
    assert!(options.contains(&format!("value=\"{mac}\"")), "the client");
    assert!(
        !before.contains(mac) && !after.contains(mac),
        "the MAC only inside the select"
    );
    Ok(())
}
