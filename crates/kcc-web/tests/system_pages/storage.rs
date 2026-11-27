//! Storage.
//!
//! Per-role controls with the eject behind the typed router name, and no partition check
//! or format routes.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::{FaultInjection, log_capture};

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

/// Todo 4: the drive Entware runs from (`opkg disk`) is not ejected: the typed name gets the
/// localized refusal, the refusal is audited and the router never hears the eject.
#[tokio::test]
async fn the_entware_drive_is_not_ejected() -> TestResult {
    let fixture = Fixture::new().await?;
    assert!(fixture.handle().configure("opkg disk fixture-media:/"));
    let admin = fixture.login("admin").await?;

    let answer = text(
        fixture
            .post(
                "/ui/r/home/system/storage/eject?media=Media0",
                &admin,
                "confirm=yes&confirm_name=home",
            )
            .await?,
    )
    .await?;

    assert!(
        answer.contains(&en(keys::DOMAINS_ENTWARE_DRIVE_IN_USE)),
        "{answer}"
    );
    assert!(
        fixture.handle().request_log().iter().all(|record| record
            .commands()
            .flatten()
            .all(|line| !line.contains("eject"))),
        "the router heard an eject"
    );
    assert_eq!(fixture.audit_flushed().await, 0);
    assert!(fixture.audited("web.storage_eject", "entware_drive_in_use")?);
    Ok(())
}

/// Todo 4: when the `opkg disk` or `show media` read fails, the eject fails closed: the
/// page answers the unreachable refusal, it is audited and the router never hears the
/// eject.
#[tokio::test]
async fn an_unread_entware_drive_is_not_ejected() -> TestResult {
    for read in ["\"rc\":{\"opkg\"", "show/media"] {
        let faults = FaultInjection::default().fail_read_matching(read, 100);
        let fixture = Fixture::with_faults(faults).await?;
        assert!(fixture.handle().configure("opkg disk fixture-media:/"));
        let admin = fixture.login("admin").await?;

        let answer = text(
            fixture
                .post(
                    "/ui/r/home/system/storage/eject?media=Media0",
                    &admin,
                    "confirm=yes&confirm_name=home",
                )
                .await?,
        )
        .await?;

        assert!(
            answer.contains(&en(keys::WEB_KIT_UNREACHABLE)),
            "{read}: {answer}"
        );
        assert!(
            fixture.handle().request_log().iter().all(|record| record
                .commands()
                .flatten()
                .all(|line| !line.contains("eject"))),
            "{read}: the router heard an eject"
        );
        assert_eq!(fixture.audit_flushed().await, 0);
        assert!(
            fixture.audited("web.storage_eject", "unreachable")?,
            "{read}"
        );
    }
    Ok(())
}

/// Todo 9: a failed USB read logs its error and the page still lists the media.
#[tokio::test]
async fn an_unread_usb_list_is_logged_and_the_media_still_show() -> TestResult {
    let (captured, _guard) = log_capture::start();
    let faults = FaultInjection::default().fail_read_matching("show/usb", 100);
    let fixture = Fixture::with_faults(faults).await?;
    let viewer = fixture.login("viewer").await?;

    let page = text(fixture.get(PAGE, &viewer).await?).await?;

    assert!(page.contains(">Media0<"), "{page}");
    let warned: Vec<String> = captured
        .lines_at("WARN")
        .into_iter()
        .filter(|line| line.contains("router USB devices could not be read"))
        .collect();
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(
        warned.iter().all(|line| line.contains("error=")),
        "{warned:?}"
    );
    Ok(())
}
