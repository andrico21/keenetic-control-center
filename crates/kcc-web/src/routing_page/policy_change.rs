//! How a connection-policy change runs: the policy found on the router, the change
//! planned and applied through the policies domain's read-back, and the policies read back.

use axum::http::HeaderMap;
use kcc_app::workflow::WorkflowError;
use kcc_domain::{
    ChangeOp, RouterCtx,
    policies::{change::apply, descriptor::DESCRIPTOR},
};
use kcc_i18n::locale::Locale;
use serde::Deserialize;

use super::{
    frame::workflow_error,
    policy_rows::{Policy, read_policies},
    policy_view::policies_region,
    reply::{Replying, gone},
};
use crate::{
    authz::CurrentUser,
    page_kit::{
        action::Action,
        change::Applied,
        gate::Controls,
        outcome::Failure,
        request::{Params, rendered, shown_query},
        submit::{Form, Planned, Submission},
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

/// The policy `name` of the router.
///
/// # Errors
///
/// Returns the failure, in `locale`, of a policy the router no longer has.
// cancel-safe: reads only.
pub(crate) async fn known(
    domain: &RouterCtx,
    name: &str,
    locale: Locale,
) -> Result<Policy, Failure> {
    find(domain, name).await.ok_or_else(|| gone(locale))
}

/// The policy changes `ops`, applied in order, each read back by the policies domain.
pub(crate) fn applied(ops: Vec<ChangeOp>) -> Planned {
    let planned = ops.clone();
    Planned::working(&planned, move |changes, context| {
        Box::pin(async move {
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
    })
}

/// `params` submitted from `form` to `action`, answered as the routing page answers, the
/// policies read back after the change, run or failed.
pub(crate) const fn submission<'call, F>(
    action: Action<'call>,
    params: &'call Params,
    form: F,
) -> Submission<'call, Replying<F>>
where
    F: Form,
{
    Submission::new(action, params, Replying::new(form)).refreshing_after_failure()
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
