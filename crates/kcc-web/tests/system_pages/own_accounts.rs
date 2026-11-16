//! The router accounts kcc signs in with, and the existence checks of the account,
//! component, storage and KeenDNS changes.
//!
//! The read-only polling login is protected like the primary one, a profile that names no
//! login protects every account, and a check that cannot read the router answers
//! unreachable instead of taking the object as absent.

use axum::http::StatusCode;
use kcc_app::settings::RouterAuth;
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_testkit::{DEFAULT_PASSWORD, FaultInjection, write_secret_file};

use crate::{
    support::{
        build::admin as admin_role,
        outcome::TestResult,
        page::{en, form, text},
        web::{Fixture, ROUTER},
    },
    users::{PAGE, add_lab, configured},
};

/// The system pages of the fixture's router.
const SYSTEM: &str = "/ui/r/home/system";

/// Posts `fields` to `path` as `admin` and requires the `refusal` in the answer.
async fn refused(
    fixture: &Fixture,
    path: &str,
    fields: &[(&str, &str)],
    refusal: MessageKey,
) -> TestResult {
    let admin = fixture.login("admin").await?;
    let answer = text(fixture.post(path, &admin, &form(fields)).await?).await?;
    assert!(answer.contains(&en(refusal)), "{path}: {answer}");
    Ok(())
}

/// W1-07, C-24: the read-only login is protected like the primary one.
///
/// It keeps its password, its tags and the account itself; the password change and the
/// delete send nothing.
#[tokio::test]
async fn the_read_only_login_is_protected_like_the_primary_one() -> TestResult {
    let fixture = Fixture::new().await?;
    let admin = fixture.login("admin").await?;
    let added = form(&[("name", "monitor"), ("tag", "readonly"), ("confirm", "yes")]);
    drop(fixture.post(PAGE, &admin, &added).await?);
    let mut profile = fixture.registry().get(ROUTER)?.profile;
    profile.read_login = Some("monitor".to_owned());
    let reader = write_secret_file(&fixture.directory(), "reader-password", DEFAULT_PASSWORD)?;
    profile.read_password_file = Some(reader);
    fixture.registry().update(&admin_role()?, profile).await?;
    let secret = format!("replacement-{}", 7_u8);
    let password = [
        ("confirm", "yes"),
        ("secret", secret.as_str()),
        ("secret_again", secret.as_str()),
    ];
    let typed = [
        ("object", "monitor"),
        ("confirm", "yes"),
        ("confirm_name", "monitor"),
    ];
    for (path, fields, refusal) in [
        (
            format!("{PAGE}/password?name=monitor"),
            &password[..],
            keys::WEB_SECRET_USER_PROTECTED,
        ),
        (
            format!("{PAGE}/delete"),
            &typed[..],
            keys::WEB_SYSTEM_USERS_PROTECTED,
        ),
    ] {
        let before = fixture.handle().request_count();
        refused(&fixture, &path, fields, refusal).await?;
        assert_eq!(
            fixture.handle().request_count(),
            before,
            "{path} sent nothing"
        );
    }
    let untagged = [("name", "monitor"), ("confirm", "yes")];
    refused(
        &fixture,
        &format!("{PAGE}/tags"),
        &untagged,
        keys::WEB_SYSTEM_USERS_PROTECTED,
    )
    .await?;
    assert_eq!(
        configured(&fixture).await?,
        [("monitor".to_owned(), vec!["readonly".to_owned()])],
        "the read-only login unchanged"
    );
    Ok(())
}

/// W4-03: a profile that names no login protects every account.
///
/// kcc cannot tell its own account under a token profile: a password change and a delete
/// are refused and send nothing.
#[tokio::test]
async fn a_profile_without_a_login_refuses_account_changes() -> TestResult {
    let fixture = Fixture::new().await?;
    drop(add_lab(&fixture).await?);
    let mut profile = fixture.registry().get(ROUTER)?.profile;
    profile.login = String::new();
    profile.password_file = None;
    profile.auth = RouterAuth::Token;
    let token = format!("token-{}", 7_u8);
    profile.token_file = Some(write_secret_file(
        &fixture.directory(),
        "router-token",
        &token,
    )?);
    fixture.registry().update(&admin_role()?, profile).await?;
    let secret = format!("replacement-{}", 7_u8);
    let password = [
        ("confirm", "yes"),
        ("secret", secret.as_str()),
        ("secret_again", secret.as_str()),
    ];
    let typed = [
        ("object", "lab"),
        ("confirm", "yes"),
        ("confirm_name", "lab"),
    ];
    for (path, fields, refusal) in [
        (
            format!("{PAGE}/password?name=lab"),
            &password[..],
            keys::WEB_SECRET_USER_PROTECTED,
        ),
        (
            format!("{PAGE}/delete"),
            &typed[..],
            keys::WEB_SYSTEM_USERS_PROTECTED,
        ),
    ] {
        let before = fixture.handle().request_count();
        refused(&fixture, &path, fields, refusal).await?;
        assert_eq!(
            fixture.handle().request_count(),
            before,
            "{path} sent nothing"
        );
    }
    Ok(())
}

/// W4-05: an existence check that cannot read the router answers unreachable.
///
/// The object is not taken as absent; "Add account" in particular never writes an
/// account it could not see.
#[tokio::test]
async fn existence_checks_that_cannot_read_the_router_answer_unreachable() -> TestResult {
    let add = [("name", "lab"), ("tag", "http"), ("confirm", "yes")];
    let confirmed = [("confirm", "yes")];
    for (read, path, fields, action) in [
        (
            "\"rc\":{\"user\"",
            PAGE.to_owned(),
            &add[..],
            "web.router_user_create",
        ),
        (
            "show/components/list",
            format!("{SYSTEM}/components/queue?name=ntfs&action=install"),
            &confirmed[..],
            "web.components_install",
        ),
        (
            "show/media",
            format!("{SYSTEM}/storage/eject?media=Media0"),
            &confirmed[..],
            "web.storage_eject",
        ),
        (
            "show/ndns",
            format!("{SYSTEM}/keendns/drop"),
            &confirmed[..],
            "web.keendns_drop",
        ),
    ] {
        let faults = FaultInjection::default().fail_read_matching(read, 100);
        let fixture = Fixture::with_faults(faults).await?;
        let admin = fixture.login("admin").await?;
        let answer = fixture.post(&path, &admin, &form(fields)).await?;
        assert_ne!(answer.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(fixture.outcomes(action)?, ["unreachable"], "{path}");
        assert!(
            fixture
                .handle()
                .request_log()
                .iter()
                .all(|record| record.command().is_none()),
            "{path} wrote nothing"
        );
    }
    Ok(())
}
