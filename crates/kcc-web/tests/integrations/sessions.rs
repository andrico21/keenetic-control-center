//! The signed-in session count behind `kcc_web_sessions`.

use core::time::Duration;

use crate::{
    support::{Fixture, TestResult},
    wiring::Options,
};

#[tokio::test]
async fn only_live_signed_in_sessions_count() -> TestResult {
    let fixture = Fixture::new(Options::default()).await?;
    assert_eq!(fixture.web().active_sessions().await, 0, "nobody signed in");
    let _first = fixture.login().await?;
    assert_eq!(
        fixture.web().active_sessions().await,
        1,
        "the login page's anonymous session does not count"
    );
    let _second = fixture.login().await?;
    assert_eq!(fixture.web().active_sessions().await, 2, "two browsers");

    fixture.clock().advance(Duration::from_hours(241));
    assert_eq!(
        fixture.web().active_sessions().await,
        0,
        "idle sessions expired"
    );
    Ok(())
}
