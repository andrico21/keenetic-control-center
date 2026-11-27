//! The row actions of the connection policies: multipath on or off, an interface taken
//! off a policy, and a policy deleted once its name is typed.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_app::workflow::WorkflowError;
use kcc_domain::{
    ChangeOp,
    policies::{
        change::{apply, plan},
        descriptor::DESCRIPTOR,
        model::PolicyPermit,
    },
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;

use super::{
    policy_change::{NameQuery, applied, find, known, refreshed, submission},
    policy_rows::configured,
    reply::gone,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    net_change::unusable,
    page_kit::{
        action::Operation,
        change::Applied,
        confirm::{Dialog, Resubmit, TypedNameForm},
        request::{Params, missing},
        respond,
        respond::Answer,
        submit::{self, Formless, Invalid, Planned},
    },
};

/// Multipath on or off, audited as `web.routing_policy_multipath`.
const MULTIPATH: Operation =
    Operation::write(&DESCRIPTOR, "multipath", "web.routing_policy_multipath");

/// An interface taken off a policy, audited as `web.routing_policy_unpermit`.
const UNPERMIT: Operation = Operation::write(&DESCRIPTOR, "permit", "web.routing_policy_unpermit");

/// A policy deleted, audited as `web.routing_policy_delete`.
const DELETE: Operation = Operation::write(&DESCRIPTOR, "policy", "web.routing_policy_delete");

/// The policy and the value a row action names.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RowQuery {
    /// The policy's name.
    #[serde(default)]
    name: String,
    /// `on` or `off`, for multipath.
    #[serde(default)]
    value: String,
    /// The interface, for Remove.
    #[serde(default)]
    interface: String,
}

/// `POST /ui/r/{router}/routing/policy/multipath?name=&value=on|off`: turns multipath of
/// the policy on or off.
///
/// # Errors
///
/// Answers 404 for a malformed value, and what the kit answers when the router or the
/// permission is missing.
// NOT cancel-safe: dropped after `submit_reading` sends the change, the router may keep it without
// its read-back, audit entry or timer cleanup.
pub(crate) async fn multipath(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<RowQuery>,
    headers: HeaderMap,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let enabled = match query.value.as_str() {
        "on" => true,
        "off" => false,
        _ => return Err(missing()),
    };
    let action = MULTIPATH.open(&state, &user, &router).await?;
    let locale = action.locale();
    let params = Params::default();
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/routing/policy/multipath"),
        "#page-outcome",
    );
    Ok(submission(action, (&params, resubmit), Formless)
        .submit_reading(
            async |_params, domain| Ok(known(domain, &query.name, locale).await?),
            async |policy, domain| {
                Ok(applied(vec![plan::multipath(
                    domain,
                    policy.name(),
                    enabled,
                )?]))
            },
            async |domain| refreshed(domain, (&router, &user), &headers, locale).await,
        )
        .await)
}

/// `POST /ui/r/{router}/routing/policy/unpermit?name=&interface=`: takes the interface off
/// the policy and checks that no line permits it any more.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
// NOT cancel-safe: dropped after `submit_reading` sends the change, the router may keep it without
// its read-back, audit entry or timer cleanup.
pub(crate) async fn unpermit(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<RowQuery>,
    headers: HeaderMap,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = UNPERMIT.open(&state, &user, &router).await?;
    let locale = action.locale();
    let params = Params::default();
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/routing/policy/unpermit"),
        "#page-outcome",
    );
    Ok(submission(action, (&params, resubmit), Formless)
        .submit_reading(
            async |_params, domain| {
                let policy = known(domain, &query.name, locale).await?;
                if policy.permit(&query.interface).is_none() {
                    return Err(gone(locale).into());
                }
                Ok(policy)
            },
            async |policy, domain| {
                let permit = PolicyPermit::new(&query.interface);
                let op = plan::permit(domain, policy.name(), &permit, false)?;
                Ok(unpermitted(
                    op,
                    policy.name().to_owned(),
                    query.interface.clone(),
                ))
            },
            async |domain| refreshed(domain, (&router, &user), &headers, locale).await,
        )
        .await)
}

/// `op`, taking `interface` off the policy `name`, read back from the running
/// configuration.
fn unpermitted(op: ChangeOp, name: String, interface: String) -> Planned {
    let operations = [op.clone()];
    Planned::working(&operations, move |changes, context| {
        Box::pin(async move {
            let result = apply::apply(changes, context, &op)
                .await
                .map_err(WorkflowError::from)?;
            let lines = configured(context).await.map_err(WorkflowError::from)?;
            let still = lines.iter().any(|(found, rows)| {
                *found == name
                    && rows.iter().any(|words| {
                        matches!(words.as_slice(), [permit, global, named, ..]
                            if permit == "permit" && global == "global" && *named == interface)
                    })
            });
            if still {
                return Err(WorkflowError::VerificationFailed {
                    field: format!("ip policy {name} permit"),
                });
            }
            Ok(Applied::Cli {
                unsaved: result.unsaved,
                responses: result.responses,
            })
        })
    })
}

/// `GET /ui/r/{router}/routing/policy/delete?name=`: asks for the policy's name.
///
/// # Errors
///
/// Answers 404 for a policy the router does not have, and what the kit answers when the
/// router or the permission is missing.
// NOT cancel-safe: a refused or failed open queues an audit entry that may be written after the
// future is dropped; otherwise it only reads.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let policy = find(&domain, query.name())
        .await
        .map_err(|message| unusable(action.locale(), &message))?
        .ok_or_else(missing)?;
    let dialog = confirmation(action.locale(), &router, policy.name());
    Ok(respond::in_dialog(errors::render(&dialog)))
}

/// `POST /ui/r/{router}/routing/policy/delete`: deletes the policy once its name is typed.
///
/// # Errors
///
/// Answers the dialog again (422) when the typed name does not match, and what the kit
/// answers when the router or the permission is missing.
// NOT cancel-safe: dropped after `submit_reading` sends the change, the router may keep it without
// its read-back, audit entry or timer cleanup.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<TypedNameForm>,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let params = Params::default();
    let dialog = Confirming(confirmation(locale, &router, form.name()));
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/routing/policy/delete"),
        "#page-outcome",
    );
    Ok(submission(action, (&params, resubmit), dialog)
        .landing_in("#page-outcome")
        .submit_reading(
            async |_params, domain| {
                let policy = known(domain, form.name(), locale).await?;
                if form.confirmed() {
                    Ok(policy)
                } else {
                    Err(Invalid::at("confirm_name", keys::WEB_ADMIN_ERROR_CONFIRM).into())
                }
            },
            async |policy, domain| Ok(applied(vec![plan::remove(domain, policy.name())?])),
            async |domain| refreshed(domain, (&router, &user), &headers, locale).await,
        )
        .await)
}

/// The typed-name confirmation of a deletion, shown again with why it was not enough.
struct Confirming(Dialog);

impl submit::Form for Confirming {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let Self(mut dialog) = self;
        for (_field, rule) in invalid.into_findings() {
            dialog.set_error(tr(locale, rule, None));
        }
        respond::in_dialog(respond::unprocessable(&dialog))
    }
}

/// The typed-name confirmation deleting the policy `name` of `router`.
fn confirmation(locale: Locale, router: &str, name: &str) -> Dialog {
    Dialog::typed_name(
        locale,
        format!("/ui/r/{router}/routing/policy/delete"),
        name,
        (
            keys::WEB_ROUTING_POLICY_DELETE_TITLE,
            keys::WEB_ROUTING_POLICY_DELETE_TEXT,
        ),
    )
}
