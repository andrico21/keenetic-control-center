//! The storage page's Entware actions.
//!
//! Prepare for Entware where the router can initialize the medium with ext4, and the
//! second acknowledgement before the drive Entware runs from is ejected or initialized.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::{
    FakeRouter,
    model::{Firmware, Model, Profile},
};
use serde_json::json;

use super::{DRIVE, heard, heard_since, mark, over, ready};
use crate::support::{
    outcome::TestResult,
    page::{en, text},
};

/// The storage page.
const STORAGE: &str = "/ui/r/home/system/storage";

/// Todo 12: Prepare for Entware is offered only where it can run.
///
/// The administrator is offered it on a 5.1 router whose medium can be initialized with
/// ext4; the operator and the viewer are not, and neither is anyone on a firmware whose
/// catalog lacks `media initialize`.
#[tokio::test]
async fn prepare_for_entware_is_offered_where_it_can_run() -> TestResult {
    let prepare = format!("hx-post=\"{STORAGE}/initialize?media=Media0\"");
    let fixture = over(ready()).await?;
    for (account, offered) in [("viewer", false), ("operator", false), ("admin", true)] {
        let browser = fixture.login(account).await?;
        let page = text(fixture.get(STORAGE, &browser).await?).await?;
        assert_eq!(page.contains(&prepare), offered, "{account}");
        assert_eq!(
            page.contains(&en(keys::WEB_SYSTEM_ENTWARE_PREPARE)),
            offered,
            "{account}"
        );
    }
    let older = FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V5_0)?);
    let on_5_0 = over(older.reached_directly()).await?;
    let admin = on_5_0.login("admin").await?;
    let page = text(on_5_0.get(STORAGE, &admin).await?).await?;
    assert!(page.contains("/storage/eject?media=Media0"), "eject stays");
    assert!(!page.contains(&prepare), "5.0 has no media initialize");
    Ok(())
}

/// Todo 12: Prepare for Entware follows each medium's `initialize-supported`.
///
/// A medium the router can initialize only as `default` or `ntfs` keeps its eject but
/// offers no Prepare; the same medium with `ext4` among them offers it.
#[tokio::test]
async fn prepare_for_entware_needs_ext4_among_the_medium_s_filesystems() -> TestResult {
    for (supported, offered) in [
        (json!(["default", "ntfs"]), false),
        (json!(["default", "ext4", "ntfs"]), true),
    ] {
        let media = json!([{
            "id": "Media0", "label": "fixture-media",
            "uuid": "0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0", "filesystem": "ext4",
            "size": 8_000_000_000_u64, "free": 6_000_000_000_u64,
            "initialize-supported": supported,
        }]);
        let fixture = over(ready().show_fixture("media", media)).await?;
        let admin = fixture.login("admin").await?;
        let page = text(fixture.get(STORAGE, &admin).await?).await?;
        assert!(
            page.contains("/storage/eject?media=Media0"),
            "eject stays: {offered}"
        );
        assert_eq!(
            page.contains(&format!("hx-post=\"{STORAGE}/initialize?media=Media0\"")),
            offered,
            "ext4 offered: {offered}"
        );
    }
    Ok(())
}

/// Todo 12: Prepare for Entware asks for the router name and sends nothing before;
/// confirmed on a drive Entware does not run from, the router hears the initialize and the
/// page says it started.
#[tokio::test]
async fn prepare_for_entware_needs_the_router_name() -> TestResult {
    let fixture = over(ready()).await?;
    let admin = fixture.login("admin").await?;
    let path = format!("{STORAGE}/initialize?media=Media0");
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
    let body = text(
        fixture
            .post(&path, &admin, "confirm=yes&confirm_name=home")
            .await?,
    )
    .await?;
    assert!(
        body.contains(&en(keys::WEB_SYSTEM_ENTWARE_PREPARE_STARTED)),
        "{body}"
    );
    assert!(heard(&fixture, "media Media0 initialize ext4"));
    assert!(fixture.audited("web.storage_initialize", "success")?);
    let missing = fixture
        .post(
            &format!("{STORAGE}/initialize?media=Media9"),
            &admin,
            "confirm=yes&confirm_name=home",
        )
        .await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// Todo 12: ejecting or initializing the drive Entware runs from asks twice.
///
/// After the router name, the first confirmation sends nothing and answers the second
/// dialog, whose confirmation carries `entware_ok=yes`; only that request reaches the
/// router.
#[tokio::test]
async fn the_entware_drive_asks_twice() -> TestResult {
    for (action, command) in [
        ("eject", "system eject Media0"),
        ("initialize", "media Media0 initialize ext4"),
    ] {
        let fixture = over(ready()).await?;
        assert!(fixture.handle().configure(&format!("opkg disk {DRIVE}")));
        let admin = fixture.login("admin").await?;
        let path = format!("{STORAGE}/{action}?media=Media0");
        let first = text(
            fixture
                .post(&path, &admin, "confirm=yes&confirm_name=home")
                .await?,
        )
        .await?;
        assert!(
            first.contains(&en(keys::WEB_SYSTEM_ENTWARE_DRIVE_TITLE)),
            "{first}"
        );
        assert!(
            first.contains(&en(keys::DOMAINS_ENTWARE_DRIVE_IN_USE)),
            "{first}"
        );
        assert!(
            first.contains(&format!("{action}?media=Media0&#38;entware_ok=yes")),
            "{first}"
        );
        assert!(
            first.contains("name=\"confirm_name\""),
            "the name again: {first}"
        );
        assert!(!heard(&fixture, command), "{action}: not yet");
        let unnamed = text(fixture.post(&path, &admin, "entware_ok=yes").await?).await?;
        assert!(
            unnamed.contains(&en(keys::WEB_KIT_CONFIRM_DESTRUCTIVE_TITLE)),
            "the acknowledgement alone is not the router name: {unnamed}"
        );
        assert!(!heard(&fixture, command), "{action}: not yet");
        drop(
            fixture
                .post(
                    &path,
                    &admin,
                    "confirm=yes&confirm_name=home&entware_ok=yes",
                )
                .await?,
        );
        assert!(heard(&fixture, command), "{action}: acknowledged twice");
    }
    Ok(())
}

/// Todo 12: a drive Entware does not run from is ejected after the router name alone.
#[tokio::test]
async fn another_drive_asks_once() -> TestResult {
    let fixture = over(ready()).await?;
    let admin = fixture.login("admin").await?;
    let body = text(
        fixture
            .post(
                &format!("{STORAGE}/eject?media=Media0"),
                &admin,
                "confirm=yes&confirm_name=home",
            )
            .await?,
    )
    .await?;
    assert!(
        !body.contains(&en(keys::WEB_SYSTEM_ENTWARE_DRIVE_TITLE)),
        "{body}"
    );
    assert!(heard(&fixture, "system eject Media0"), "{body}");
    Ok(())
}
