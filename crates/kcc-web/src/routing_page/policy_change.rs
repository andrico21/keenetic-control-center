//! How a connection-policy change runs: the policy found on the router, the change
//! planned and applied through the policies domain's read-back, and the policies read back.

use axum::{http::HeaderMap, response::Response};
use kcc_app::workflow::WorkflowError;
use kcc_catalog::Risk;
use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    policies::{change::apply, descriptor::DESCRIPTOR},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;

use super::{
    frame::workflow_error,
    policy_rows::{Policy, read_policies},
    policy_view::policies_region,
    reply::answer,
};
use crate::{
    authz::CurrentUser,
    page_kit::{
        action::Action,
        change::Applied,
        failure::plan_failure,
        family::Family,
        gate::Controls,
        outcome::{Failure, Outcome},
        request::{rendered, shown_query},
        respond::Answer,
    },
};

/// The policy an action names.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct NameQuery {
    /// The policy's name.
    #[serde(default)]
    name: String,
}

impl NameQuery {
    /// The policy's name, as typed.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

/// The policy `name` of the router, when it has it.
// cancel-safe: reads only.
pub(crate) async fn find(domain: &RouterCtx, name: &str) -> Option<Policy> {
    read_policies(domain)
        .await
        .ok()?
        .into_iter()
        .find(|policy| policy.name() == name)
}

/// `action` again with the policy `name`, when the router has it.
///
/// # Errors
///
/// Answers the audited "no longer there" outcome otherwise.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn known<'call>(
    action: Action<'call>,
    domain: &RouterCtx,
    name: &str,
) -> Result<(Action<'call>, Policy), Answer> {
    if let Some(policy) = find(domain, name).await {
        return Ok((action, policy));
    }
    let locale = action.locale();
    action.abandon("gone").await;
    Err(answer(gone(locale), None, locale).into())
}

/// Runs the policy changes `planned`, or answers why they could not be planned.
// NOT cancel-safe: see `Action::run_with`.
pub(crate) async fn planned_change(
    action: Action<'_>,
    domain: &RouterCtx,
    planned: Result<Vec<ChangeOp>, DomainError>,
    page: (&HeaderMap, &CurrentUser),
) -> Response {
    match planned {
        Ok(ops) => finish(action, domain, ops, page).await,
        Err(error) => {
            let locale = action.locale();
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            answer(Outcome::failed(failure), None, locale)
        }
    }
}

/// Applies `ops` in order, each read back by the policies domain, and answers with the
/// outcome and the policies read back.
// NOT cancel-safe: see `Action::run_with`.
async fn finish(
    action: Action<'_>,
    domain: &RouterCtx,
    ops: Vec<ChangeOp>,
    (headers, user): (&HeaderMap, &CurrentUser),
) -> Response {
    let locale = action.locale();
    let router = action.router();
    let outcome = action
        .run_with(Risk::Write, async |changes, context| {
            let mut last = None;
            for op in &ops {
                last = Some(
                    apply::apply(changes, context, op)
                        .await
                        .map_err(workflow_error)?,
                );
            }
            let result = last.ok_or(WorkflowError::InvalidResponse)?;
            Ok(Applied::Cli {
                unsaved: result.unsaved,
                responses: result.responses,
            })
        })
        .await;
    let refreshed = refreshed(domain, (router, user), headers, locale).await;
    answer(outcome, refreshed, locale)
}

/// The policies region read back for the page of `headers`, out of band.
// cancel-safe: reads only.
pub(crate) async fn refreshed(
    domain: &RouterCtx,
    (router, user): (&str, &CurrentUser),
    headers: &HeaderMap,
    locale: Locale,
) -> Option<String> {
    let controls = Controls::new(user.role(), router)
        .with_operations(DESCRIPTOR.write_ops, Some(&domain.catalog));
    policies_region(domain, (router, &shown_query(headers)), (controls, locale))
        .await
        .ok()
        .and_then(|region| rendered(&region.out_of_band()))
}

/// The failure of a policy the router no longer has, in `locale`.
pub(crate) fn gone(locale: Locale) -> Outcome {
    Outcome::failed(Failure::new(
        tr(locale, keys::WEB_ROUTING_GONE, None),
        "gone",
    ))
}
