//! Storage.
//!
//! Per-role controls with the partition actions the catalog lacks kept hidden, the eject
//! behind the typed router name that the fake refuses, and a partition format refused by
//! the catalog before anything is sent.

use axum::http::StatusCode;
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    audited, en, html,
    support::{Fixture, ROUTER, TestResult, text},
};

/// The page under test.
const PAGE: &str = "/ui/r/home/system/storage";

#[tokio::test]
async fn each_role_sees_the_media_and_only_the_actions_the_catalog_has() -> TestResult {
    let fixture = Fixture::new().await?;
    let eject = "hx-post=\"/ui/r/home/system/storage/eject?media=Media0\"";
    for (account, ejects) in [("viewer", false), ("operator", false), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let response = fixture.get(PAGE, &browser).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            ">Media0<",
            "fixture-media",
            ">ext4<",
            "fixture-vendor fixture-storage",
        ] {
            assert!(page.contains(shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(eject), ejects, "{account} eject");
        assert!(
            !page.contains("/system/storage/check") && !page.contains("/system/storage/format"),
            "{account}: the catalog has no partition check or format"
        );
    }
    Ok(())
}

#[tokio::test]
async fn eject_needs_the_router_name_and_shows_the_router_refusal() -> TestResult {
    let fixture = Fixture::new().await?;
    let eject = format!("{PAGE}/eject?media=Media0");
    let operator = fixture.login("operator").await?;
    let denied = fixture.post(&eject, &operator, "").await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN, "operator");
    let admin = fixture.login("admin").await?;
    let unknown = fixture
        .post(&format!("{PAGE}/eject?media=Media9"), &admin, "")
        .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND, "unknown medium");
    let asked = text(fixture.post(&eject, &admin, "").await?).await?;
    assert!(
        asked.contains("hx-post=\"/ui/r/home/system/storage/eject?media=Media0\""),
        "asks and sends the medium again: {asked}"
    );
    let before = fixture.handle().request_count();
    let mistyped = text(
        fixture
            .post(&eject, &admin, "confirm=yes&confirm_name=Home")
            .await?,
    )
    .await?;
    let mut args = FluentArgs::new();
    args.set("router", ROUTER);
    let mismatch = html(&tr(
        Locale::En,
        keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
        Some(&args),
    ));
    assert!(mistyped.contains(&mismatch), "refused: {mistyped}");
    let refused = text(
        fixture
            .post(&eject, &admin, "confirm=yes&confirm_name=home")
            .await?,
    )
    .await?;
    assert!(refused.contains(&en(keys::WEB_KIT_REJECTED)), "{refused}");
    assert!(
        refused.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
        "router said"
    );
    assert!(
        fixture.handle().request_count() > before,
        "the confirmed eject reached the router"
    );
    assert!(
        audited(&fixture, "web.storage_eject", "rci_error")?,
        "audited"
    );
    Ok(())
}

#[tokio::test]
async fn a_format_the_catalog_lacks_is_refused_before_anything_is_sent() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let format = format!("{PAGE}/format?media=Media0&filesystem=ext4");
    drop(fixture.post(&format, &admin, "").await?);
    let before = fixture.audit()?.len();
    let response = fixture
        .post(&format, &admin, "confirm=yes&confirm_name=home")
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "refused"
    );
    let body = text(response).await?;
    assert!(body.contains(&en(keys::WEB_KIT_INVALID)), "{body}");
    let audit = fixture.audit()?;
    assert!(
        audit
            .iter()
            .skip(before)
            .all(|entry| entry.action != "router.change_cli"),
        "nothing sent"
    );
    assert!(
        audited(&fixture, "web.storage_format", "validation_failed")?,
        "audited"
    );
    Ok(())
}
