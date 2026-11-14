//! Storage.
//!
//! Per-role controls with the partition actions the catalog lacks kept hidden, the eject
//! behind the typed router name that the fake refuses, and a partition format refused by
//! the catalog before anything is sent.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::support::{
    outcome::TestResult,
    page::{en, text},
    web::Fixture,
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
        fixture.audited("web.storage_format", "validation_failed")?,
        "audited"
    );
    Ok(())
}
