//! Storage.
//!
//! Per-role controls with the eject behind the typed router name, and no partition check
//! or format routes.

use axum::http::StatusCode;

use crate::support::{outcome::TestResult, page::text, web::Fixture};

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
            "{account}: kcc offers no partition check or format"
        );
    }
    Ok(())
}

/// C-10: the partition check and format routes are gone; the eject route stays.
#[tokio::test]
async fn the_removed_check_and_format_routes_are_not_found() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    for path in ["check", "format"] {
        let response = fixture
            .post(&format!("{PAGE}/{path}?media=Media0"), &admin, "")
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    Ok(())
}
