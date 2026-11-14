//! The migration wizard over HTTP against fake routers: the steps from a KN-1010 to a
//! KN-1811, resuming after a reload, and the guards around them.

#[path = "migration_wizard/apply_failure.rs"]
mod apply_failure;
#[path = "migration_wizard/apply_flow.rs"]
mod apply_flow;
#[path = "migration_wizard/flow.rs"]
mod flow;
#[path = "migration_wizard/guards.rs"]
mod guards;
#[path = "migration_wizard/operator_guards.rs"]
mod operator_guards;
#[path = "migration_wizard/plan_agreement.rs"]
mod plan_agreement;
#[path = "migration_wizard/plan_screens.rs"]
mod plan_screens;
#[path = "migration_wizard/plan_steps.rs"]
mod plan_steps;
#[path = "migration_wizard/preview.rs"]
mod preview;
#[path = "migration_wizard/records.rs"]
mod records;
#[path = "migration_wizard/secrets.rs"]
mod secrets;
#[path = "migration_wizard/setup.rs"]
mod setup;
#[path = "migration_wizard/steps.rs"]
mod steps;
#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;
#[path = "migration_wizard/switch_ports.rs"]
mod switch_ports;

use axum::response::Response;

use crate::support::{
    outcome::TestResult,
    page::header_text,
    web::{Browser, Fixture},
};

/// Starts a migration as `browser` and returns its page path.
///
/// # Errors
///
/// Returns a request failure or an answer without the redirect.
pub(crate) async fn start(fixture: &Fixture, browser: &Browser) -> TestResult<String> {
    let response = fixture
        .post_form("/ui/migrate", browser, &[("mode", "migrate")])
        .await?;
    header_text(&response, "hx-redirect").ok_or_else(|| "no redirect to the migration".into())
}

/// The redirect a step submit answered with.
///
/// # Errors
///
/// Returns an answer without the redirect.
pub(crate) fn redirected(response: &Response) -> TestResult<String> {
    header_text(response, "hx-redirect")
        .ok_or_else(|| format!("no redirect, status {}", response.status()).into())
}
