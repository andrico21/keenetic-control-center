//! The router-refusal contract of the router pages.
//!
//! A change the router refuses shows the localized refusal and only the router's own
//! words, reads nothing back, leaves no recovery timer armed, and is audited as
//! `rci_error`.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_testkit::FaultInjection;

use super::{
    outcome::TestResult,
    page::{en, router_said, text},
    web::Fixture,
};

/// What the fake router answers a line it was told to refuse.
const REFUSAL: &str = "injected parser failure.";

/// One change the router refuses.
#[expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "the rows are written as struct literals in each suite"
)]
pub(crate) struct Refusal<'row> {
    /// The audit action of the change; it names the row.
    pub(crate) action: &'row str,
    /// The command the fake router refuses once.
    pub(crate) refused: &'row str,
    /// Who posts the change.
    pub(crate) account: &'row str,
    /// The change: its path and its encoded form.
    pub(crate) post: (&'row str, &'row str),
    /// Request text the router's words must not repeat.
    pub(crate) unsaid: &'row str,
    /// Markup the answer must not carry: the unsaved badge and read-back regions.
    pub(crate) absent: &'row [&'row str],
    /// Whether the running configuration stays as it was: a change of several lines
    /// may have applied those before the refused one.
    pub(crate) unchanged: bool,
}

/// Fails with the row's name and `what` unless `holds`.
fn ensure(holds: bool, row: &str, what: &str) -> TestResult {
    if holds {
        Ok(())
    } else {
        Err(format!("{row}: {what}").into())
    }
}

/// Posts every row's change to a fresh router that refuses it and checks the answer.
///
/// # Errors
///
/// Names the first row whose answer breaks the contract.
// NOT cancel-safe: each row's fixture starts router and application tasks.
pub(crate) async fn router_refusals(rows: &[Refusal<'_>]) -> TestResult {
    for row in rows {
        let name = row.action;
        let faults = FaultInjection::default().fail_parse_matching(row.refused, 1);
        let fixture = Fixture::with_faults(faults).await?;
        let browser = fixture.login(row.account).await?;
        let before = fixture.handle().running_config_text();
        let (path, form) = row.post;
        let response = fixture.post(path, &browser, form).await?;
        ensure(response.status() == StatusCode::OK, name, "answered")?;
        let body = text(response).await?;
        ensure(body.contains(&en(keys::WEB_KIT_REJECTED)), name, &body)?;
        ensure(
            body.contains(&en(keys::WEB_EXPLORER_ROUTER_SAID)),
            name,
            "router said",
        )?;
        let said = router_said(&body).ok_or_else(|| format!("{name}: no router-said list"))?;
        ensure(said.contains(REFUSAL), name, "the router's words")?;
        ensure(
            !said.contains(row.unsaid),
            name,
            &format!("no request: {said}"),
        )?;
        for absent in row.absent {
            ensure(!body.contains(absent), name, &format!("no {absent}"))?;
        }
        ensure(
            !body.contains(&en(keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED)),
            name,
            "the timer was disarmed",
        )?;
        let after = fixture.handle().running_config_text();
        ensure(!row.unchanged || after == before, name, "changed nothing")?;
        ensure(fixture.audited(row.action, "rci_error")?, name, "audited")?;
    }
    Ok(())
}
