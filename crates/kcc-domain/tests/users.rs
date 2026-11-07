//! Router-user domain integration coverage.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use std::fs;

use kcc_app::audit::AUDIT_FILE_NAME;
use kcc_domain::{DomainError, router_users};
use kcc_testkit::DEFAULT_LOGIN;
use secrecy::SecretString;

use crate::support::{Fixture, TestResult, TraceCapture};

#[tokio::test]
async fn create_with_tags_is_visible_through_show_rc_user() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let operation = router_users::plan_create(fixture.context(), "operator", &["cli", "readonly"])?;
    let request = router_users::change_request(&operation)?;
    let mut changes = fixture.changes().await?;
    drop(changes.apply_cli(request).await?);
    drop(changes);

    let users = router_users::read_users(fixture.context()).await?;
    let operator = users
        .iter()
        .find(|user| user.name.as_deref() == Some("operator"))
        .ok_or("created operator missing")?;
    assert_eq!(operator.tags, ["cli", "readonly"]);
    fixture.shutdown().await
}

#[tokio::test]
async fn protected_account_refusals_send_no_router_request() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let before = fixture.handle().request_count();

    assert!(matches!(
        router_users::plan_tag(fixture.context(), "admin", "cli", false),
        Err(DomainError::ProtectedAccount)
    ));
    assert!(matches!(
        router_users::plan_delete(fixture.context(), DEFAULT_LOGIN, DEFAULT_LOGIN),
        Err(DomainError::ProtectedAccount)
    ));
    assert!(matches!(
        router_users::plan_password(
            fixture.context(),
            DEFAULT_LOGIN,
            DEFAULT_LOGIN,
            SecretString::from("replacement"),
        ),
        Err(DomainError::ProtectedAccount)
    ));
    assert_eq!(fixture.handle().request_count(), before);
    fixture.shutdown().await
}

#[tokio::test]
async fn password_write_hashes_and_never_exposes_plaintext() -> TestResult {
    let trace = TraceCapture::install();
    let fixture = Fixture::spawn().await?;
    let secret = "\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c} with spaces \"quotes\"";
    // Not the fixture's own login: the fake router (like a real one) ends the sessions of an
    // account whose password changes, which would make the fixture's follow-up reads fail.
    let operation = router_users::plan_password(
        fixture.context(),
        "operator",
        DEFAULT_LOGIN,
        SecretString::from(secret.to_owned()),
    )?;
    assert!(!format!("{operation:?}").contains(secret));
    assert!(!serde_json::to_string(&operation.requests)?.contains(secret));
    let request = router_users::change_request(&operation)?;
    assert!(!format!("{request:?}").contains(secret));
    assert!(!serde_json::to_string(&request)?.contains(secret));
    let mut changes = fixture.changes().await?;

    let result = changes.apply_cli(request).await?;
    let users = router_users::read_users(fixture.context()).await?;

    assert!(!format!("{result:?}").contains(secret));
    assert!(!serde_json::to_string(&result)?.contains(secret));
    assert!(!format!("{users:?}").contains(secret));
    assert!(!serde_json::to_string(&users)?.contains(secret));
    assert!(
        fixture
            .handle()
            .running_config_text()
            .contains("password md5")
    );
    assert!(!fixture.handle().running_config_text().contains(secret));
    assert!(!format!("{:?}", fixture.handle().request_log()).contains(secret));
    let audit = fs::read(fixture.state_dir().join(AUDIT_FILE_NAME))?;
    assert!(!String::from_utf8(audit)?.contains(secret));
    assert!(!trace.text()?.contains(secret));
    drop(changes);
    fixture.shutdown().await
}

#[tokio::test]
async fn password_control_character_is_refused_before_router_request() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let before = fixture.handle().request_count();

    let result = router_users::plan_password(
        fixture.context(),
        DEFAULT_LOGIN,
        "operator",
        SecretString::from("bad\npassword".to_owned()),
    );

    assert!(matches!(result, Err(DomainError::Validation { issues: _ })));
    assert_eq!(fixture.handle().request_count(), before);
    fixture.shutdown().await
}
