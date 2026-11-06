//! Router-user domain integration coverage.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_domain::{DomainError, router_users};
use kcc_testkit::DEFAULT_LOGIN;

use crate::support::{Fixture, TestResult};

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
    assert_eq!(fixture.handle().request_count(), before);
    fixture.shutdown().await
}
