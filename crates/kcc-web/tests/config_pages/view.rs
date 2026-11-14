//! What each role sees and may do on the page, and the router scope.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    PAGE,
    support::{
        outcome::TestResult,
        page::{en, form, text},
        web::Fixture,
    },
};

#[tokio::test]
async fn each_role_sees_the_state_and_only_the_controls_it_may_use() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let created = fixture.post(&format!("{PAGE}/backups"), &admin, "").await?;
    assert_eq!(created.status(), StatusCode::OK, "a backup to act on");
    let create = "hx-post=\"/ui/r/home/config/backups\"";
    let upload = "hx-get=\"/ui/r/home/config/upload\"";
    let full = "&#38;full=yes\" download";
    let delete = "/config/backups/delete?name=";
    let raw = "/config/backups/raw-restore?name=";
    for (account, writes, destroys) in [
        ("viewer", false, false),
        ("operator", true, false),
        ("admin", true, true),
    ] {
        let signed = fixture.login(account).await?;
        let response = fixture.get(PAGE, &signed).await?;
        assert_eq!(response.status(), StatusCode::OK, "{account}");
        let page = text(response).await?;
        for shown in [
            en(keys::WEB_CONFIG_TITLE),
            en(keys::WEB_CONFIG_SAVED),
            en(keys::WEB_CONFIG_NOT_ARMED_LABEL),
            en(keys::WEB_CONFIG_REASON_MANUAL),
            en(keys::WEB_CONFIG_COMPARE_RUNNING),
        ] {
            assert!(page.contains(&shown), "{account} misses {shown}");
        }
        assert_eq!(page.contains(create), writes, "{account} create");
        assert_eq!(page.contains(upload), writes, "{account} upload");
        assert_eq!(page.contains(full), destroys, "{account} full download");
        assert_eq!(page.contains(delete), destroys, "{account} delete");
        assert_eq!(page.contains(raw), destroys, "{account} raw restore");
        assert!(
            page.contains(&en(keys::WEB_CONFIG_DOWNLOAD_REDACTED)),
            "{account} downloads without secrets"
        );
        assert!(
            !page.contains("/config/save\""),
            "{account}: nothing unsaved, no Save"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_viewer_cannot_change_anything() -> TestResult {
    let fixture = Fixture::new().await?;
    let viewer = fixture.login("viewer").await?;
    for path in [
        "/backups",
        "/backups/upload",
        "/backups/delete?name=1700000000-manual.txt",
        "/backups/raw-restore?name=1700000000-manual.txt",
        "/save",
        "/commit",
        "/rollback",
    ] {
        let response = fixture.post(&format!("{PAGE}{path}"), &viewer, "").await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let dialog = fixture.get(&format!("{PAGE}/upload"), &viewer).await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "upload dialog");
    let full = fixture
        .get(
            &format!("{PAGE}/backups/download?name=1700000000-manual.txt&full=yes"),
            &viewer,
        )
        .await?;
    assert_eq!(full.status(), StatusCode::FORBIDDEN, "secrets");
    assert!(
        fixture.audited("web.config_backup_create", "forbidden")?,
        "refusals are audited"
    );
    assert!(
        fixture.audited("web.config_backup_download", "forbidden")?,
        "the secret download refusal too"
    );
    assert_eq!(fixture.backups()?, 0, "nothing stored");
    Ok(())
}

#[tokio::test]
async fn the_router_must_exist_and_be_in_scope() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    for missing in ["/ui/r/nope/config", "/ui/r/Bad!/config"] {
        let response = fixture.get(missing, &admin).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
    let outsider = fixture.login("outsider").await?;
    let page = fixture.get(PAGE, &outsider).await?;
    assert_eq!(page.status(), StatusCode::FORBIDDEN, "out of scope");
    let create = fixture
        .post(&format!("{PAGE}/backups"), &outsider, "")
        .await?;
    assert_eq!(create.status(), StatusCode::FORBIDDEN, "no action either");
    let landing = text(fixture.get("/ui/configuration", &admin).await?).await?;
    assert!(
        landing.contains("href=\"/ui/r/home/config\""),
        "the landing links the page: {landing}"
    );
    let confirmed = form(&[("confirm", "yes"), ("confirm_name", "home")]);
    let gone = fixture
        .post(
            &format!("{PAGE}/backups/delete?name=1700000000-manual.txt"),
            &admin,
            &confirmed,
        )
        .await?;
    assert_eq!(gone.status(), StatusCode::NOT_FOUND, "unknown backup");
    Ok(())
}
