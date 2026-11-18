//! A dead audit writer on the Web: one that dies on the bracket's first receipt still lets
//! the bracket disarm, and one already dead refuses the next change before any router
//! request.

use std::{fs::OpenOptions, io::Write as _};

use axum::http::StatusCode;
use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
use kcc_i18n::keys;
use kcc_testkit::{FaultInjection, bracket::Recovery};

use super::{ARMED_KEYS, commands, fixture};
use crate::support::{
    outcome::TestResult,
    page::{en, form, text},
    web::{Browser, Fixture},
};

/// The CLI console's management change.
const MANAGEMENT: &[(&str, &str)] = &[("line", "ip http port 8082"), ("confirm", "yes")];

/// A signed-in fixture whose audit writer dies on its next append: that append finds a
/// last line that is not an audit entry.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
async fn doomed() -> TestResult<(Fixture, Browser)> {
    let fixture = fixture("router", FaultInjection::default()).await?;
    let browser = fixture.login("admin").await?;
    let _lock = StateStore::open(&fixture.state_dir())?.lock(AUDIT_FILE_NAME)?;
    OpenOptions::new()
        .append(true)
        .open(fixture.state_dir().join(AUDIT_FILE_NAME))?
        .write_all(b"not an entry\n")?;
    Ok((fixture, browser))
}

/// The page of a console post, which must be answered.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
async fn page(fixture: &Fixture, browser: &Browser, pairs: &[(&str, &str)]) -> TestResult<String> {
    let response = fixture
        .post("/ui/r/home/console/cli/send", browser, &form(pairs))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    text(response).await
}

/// The arm's receipt kills the writer: the change fails, the disarm still goes out and the
/// timer is off.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn a_writer_dying_after_the_arm_still_disarms() -> TestResult {
    let (fixture, browser) = doomed().await?;

    let body = page(&fixture, &browser, MANAGEMENT).await?;

    assert!(body.contains(&en(keys::WEB_EXPLORER_FAILED)), "{body}");
    for key in ARMED_KEYS {
        assert!(!body.contains(&en(key)), "the timer is off: {body}");
    }
    let sent = commands(&fixture);
    assert_eq!(
        sent.first().map(String::as_str),
        Some(Recovery::FailSafeTimer.arm()),
        "{sent:?}"
    );
    assert_eq!(
        sent.last().map(String::as_str),
        Some(Recovery::FailSafeTimer.disarm()),
        "{sent:?}"
    );
    assert!(!fixture.handle().recovery_armed(), "the timer is off");
    Ok(())
}

/// Once an ordinary write's receipt killed the writer, a management change is refused
/// before kcc sends anything.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn a_dead_writer_refuses_the_change_before_any_router_request() -> TestResult {
    let (fixture, browser) = doomed().await?;
    let ordinary = [("line", "system country DE"), ("confirm", "yes")];
    drop(page(&fixture, &browser, &ordinary).await?);
    let before = fixture.handle().request_count();

    let body = page(&fixture, &browser, MANAGEMENT).await?;

    assert!(body.contains(&en(keys::WEB_EXPLORER_FAILED)), "{body}");
    assert_eq!(
        fixture.handle().request_count(),
        before,
        "no router request"
    );
    Ok(())
}
