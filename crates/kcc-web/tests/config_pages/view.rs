//! What each role sees and may do on the page, and the router scope.

use axum::http::StatusCode;
use kcc_i18n::keys;

use crate::{
    PAGE, audited, en, form, get, post, sign_in,
    support::{Fixture, TestResult, text},
};

#[tokio::test]
async fn each_role_sees_the_state_and_only_the_controls_it_may_use() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = sign_in(&fixture, "admin").await?;
    let created = post(&fixture, &admin, (&format!("{PAGE}/backups"), "")).await?;
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
        let signed = sign_in(&fixture, account).await?;
        let response = get(&fixture, &signed, PAGE).await?;
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
    let viewer = sign_in(&fixture, "viewer").await?;
    for path in [
        "/backups",
        "/backups/upload",
        "/backups/delete?name=1700000000-manual.txt",
        "/backups/raw-restore?name=1700000000-manual.txt",
        "/save",
        "/commit",
        "/rollback",
    ] {
        let response = post(&fixture, &viewer, (&format!("{PAGE}{path}"), "")).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path}");
    }
    let dialog = get(&fixture, &viewer, &format!("{PAGE}/upload")).await?;
    assert_eq!(dialog.status(), StatusCode::FORBIDDEN, "upload dialog");
    let full = get(
        &fixture,
        &viewer,
        &format!("{PAGE}/backups/download?name=1700000000-manual.txt&full=yes"),
    )
    .await?;
    assert_eq!(full.status(), StatusCode::FORBIDDEN, "secrets");
    assert!(
        audited(&fixture, "web.config_backup_create", "forbidden")?,
        "refusals are audited"
    );
    assert!(
        audited(&fixture, "web.config_backup_download", "forbidden")?,
        "the secret download refusal too"
    );
    assert_eq!(fixture.backups()?, 0, "nothing stored");
    Ok(())
}

#[tokio::test]
async fn the_router_must_exist_and_be_in_scope() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = sign_in(&fixture, "admin").await?;
    for missing in ["/ui/r/nope/config", "/ui/r/Bad!/config"] {
        let response = get(&fixture, &admin, missing).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{missing}");
    }
    let outsider = sign_in(&fixture, "outsider").await?;
    let page = get(&fixture, &outsider, PAGE).await?;
    assert_eq!(page.status(), StatusCode::FORBIDDEN, "out of scope");
    let create = post(&fixture, &outsider, (&format!("{PAGE}/backups"), "")).await?;
    assert_eq!(create.status(), StatusCode::FORBIDDEN, "no action either");
    let landing = text(get(&fixture, &admin, "/ui/configuration").await?).await?;
    assert!(
        landing.contains("href=\"/ui/r/home/config\""),
        "the landing links the page: {landing}"
    );
    let confirmed = form(&[("confirm", "yes"), ("confirm_name", "home")]);
    let gone = post(
        &fixture,
        &admin,
        (
            &format!("{PAGE}/backups/delete?name=1700000000-manual.txt"),
            &confirmed,
        ),
    )
    .await?;
    assert_eq!(gone.status(), StatusCode::NOT_FOUND, "unknown backup");
    Ok(())
}
