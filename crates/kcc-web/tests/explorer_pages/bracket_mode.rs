//! A router whose recovery mechanism is undecidable is refused and receives nothing.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::{FakeRouter, migration, model::Profile};

use super::commands;
use crate::{
    en, form,
    support::{Fixture, TestResult, text},
};

/// A router with neither a known mode nor a fail-safe timer shows the mode-unknown message.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn recovery_mechanism_follows_the_reported_mode() -> TestResult {
    for (mode, omit_fail_safe) in [(Some("bridge"), false), (None, true)] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = mode.map(str::to_owned);
        scenario.omit_fail_safe = omit_fail_safe;
        let fake = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario);
        let fixture = Fixture::with_router(fake).await?;
        let browser = fixture.login("admin").await?;
        let request = form(&[("line", "ip http port 8082"), ("confirm", "yes")]);

        let response = fixture
            .post("/ui/r/home/console/cli/send", &browser, &request)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = text(response).await?;
        let label = format!("{mode:?} omit={omit_fail_safe}: {body}");
        assert!(body.contains(&en(keys::MANAGEMENT_MODE_UNKNOWN)), "{label}");
        assert!(commands(&fixture).is_empty(), "nothing is sent: {label}");
        let config = fixture.handle().running_config_text();
        assert!(!config.contains("port 8082"), "{label}");
    }
    Ok(())
}
