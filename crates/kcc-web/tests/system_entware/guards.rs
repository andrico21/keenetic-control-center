//! The guards every action keeps: a role without the action's permission is refused before
//! the router hears anything, and a request without the session's CSRF token is refused.

use axum::http::StatusCode;

use super::{DRIVE, PAGE, mark, over, ready};
use crate::support::{outcome::TestResult, page::text, web::Fixture};

/// Every action of the Entware page and the storage page's Prepare for Entware: its path,
/// its form, its audit action and whether the operator holds what it needs.
const ACTIONS: [(&str, &str, &str, bool); 7] = [
    (
        "entware/chroot?on=true",
        "confirm=yes",
        "web.entware_chroot",
        true,
    ),
    (
        "entware/timezone",
        "timezone=auto",
        "web.entware_timezone",
        true,
    ),
    (
        "entware/dns-override?on=true",
        "confirm=yes",
        "web.entware_dns_override",
        true,
    ),
    (
        "entware/initrc",
        "path=/opt/x&confirm=yes&confirm_name=home",
        "web.entware_initrc",
        false,
    ),
    (
        "entware/remove",
        "confirm=yes&confirm_name=home",
        "web.entware_remove",
        false,
    ),
    (
        "entware/setup",
        "drive=fixture-media:/&confirm=yes&confirm_name=home",
        "web.entware_setup",
        false,
    ),
    (
        "storage/initialize?media=Media0",
        "confirm=yes&confirm_name=home&entware_ok=yes",
        "web.storage_initialize",
        false,
    ),
];

/// A router with Entware set up on the fixture drive.
async fn set_up() -> TestResult<Fixture> {
    let fixture = over(ready()).await?;
    assert!(fixture.handle().configure(&format!("opkg disk {DRIVE}")));
    Ok(fixture)
}

/// Todo 12: the viewer, and the operator for every destructive action, is refused with 403
/// before any request reaches the router; the refusal is audited.
#[tokio::test]
async fn roles_without_the_permission_are_refused_before_any_request() -> TestResult {
    let fixture = set_up().await?;
    let viewer = fixture.login("viewer").await?;
    let operator = fixture.login("operator").await?;
    for (path, form, audited, operator_may) in ACTIONS {
        let url = format!("/ui/r/home/system/{path}");
        let mut refused = vec![("viewer", &viewer)];
        if !operator_may {
            refused.push(("operator", &operator));
        }
        for (account, browser) in refused {
            let before = mark(&fixture);
            let response = fixture.post(&url, browser, form).await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{account} {path}");
            assert_eq!(
                mark(&fixture),
                before,
                "{account} {path}: the router heard nothing"
            );
        }
        assert!(fixture.audited(audited, "forbidden")?, "{audited}");
    }
    Ok(())
}

/// Todo 12: a post without the session's CSRF token is refused, even from an
/// administrator, and the router hears nothing.
#[tokio::test]
async fn posts_without_the_csrf_token_are_refused() -> TestResult {
    let fixture = set_up().await?;
    let admin = fixture.login("admin").await?;
    drop(fixture.get(PAGE, &admin).await?);
    for (path, form, _, _) in ACTIONS {
        let url = format!("/ui/r/home/system/{path}");
        let before = mark(&fixture);
        let response = fixture.post_without_token(&url, &admin, form).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
        assert_eq!(mark(&fixture), before, "{path}: the router heard nothing");
    }
    Ok(())
}

/// Todo 12: the viewer sees the page but no control that would post.
#[tokio::test]
async fn the_viewer_sees_no_action() -> TestResult {
    let fixture = set_up().await?;
    let viewer = fixture.login("viewer").await?;
    let page = text(fixture.get(PAGE, &viewer).await?).await?;
    assert!(
        !page.contains("hx-post=\"/ui/r/home/system/entware"),
        "{page}"
    );
    assert!(
        !page.contains("<form class=\"form\" id=\"entware-"),
        "{page}"
    );
    Ok(())
}
