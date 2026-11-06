//! Schedule, KeenDNS, and logging integration coverage.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

mod support;

use kcc_catalog::Risk;
use kcc_domain::{
    DomainError,
    keendns::{self, RemoteSecurityLevel},
    logging,
    schedules::{self, ActionTime, ScheduleAction},
};

use crate::support::{Fixture, TestResult, administrator};

#[tokio::test]
async fn schedule_read_and_action_plan_are_typed() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let schedules = schedules::read_schedules(fixture.context()).await?;
    assert_eq!(
        schedules.first().and_then(|item| item.name.as_deref()),
        Some("Schedule0")
    );
    let action = schedules::plan_action(
        fixture.context(),
        "Schedule0",
        ActionTime::new(ScheduleAction::Start, 30, 8, 1),
    )?;
    assert_eq!(action.risk, Risk::Write);
    fixture.shutdown().await
}

#[tokio::test]
async fn keendns_status_and_remote_access_risk_are_typed() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let status = keendns::read_status(fixture.context()).await?;
    assert_eq!(status.status.as_deref(), Some("registered"));
    let cloud =
        keendns::plan_cloud_security_level(fixture.context(), RemoteSecurityLevel::Private)?;
    let proxy = keendns::plan_proxy(fixture.context(), "lan-host", true)?;
    assert_eq!(cloud.risk, Risk::Management);
    assert_eq!(proxy.risk, Risk::Management);
    fixture.shutdown().await
}

#[tokio::test]
async fn log_reader_and_unconfirmed_clear_follow_safety_contract() -> TestResult {
    let fixture = Fixture::spawn().await?;
    let text = logging::read_log(fixture.context(), 10).await?;
    assert_ne!(text, "");
    let before = fixture.handle().request_count();
    let result = logging::plan_clear(fixture.context(), "router", &administrator(), false);
    assert!(matches!(result, Err(DomainError::ConfirmationRequired)));
    assert_eq!(fixture.handle().request_count(), before);
    fixture.shutdown().await
}
