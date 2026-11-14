//! The row actions of the connection policies: multipath on or off, an interface taken
//! off a policy, and a policy deleted once its name is typed.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_app::workflow::WorkflowError;
use kcc_catalog::Risk;
use kcc_domain::policies::{
    change::{apply, plan},
    descriptor::DESCRIPTOR,
    model::PolicyPermit,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;

use super::{
    frame::workflow_error,
    policy_change::{NameQuery, find, gone, known, planned_change, refreshed},
    policy_rows::configured,
    reply::answer,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page_kit::{
        action::Operation,
        change::Applied,
        context::fragment_shell,
        request::missing,
        respond,
        respond::Answer,
        typed_name::{TypedNameDialog, TypedNameForm},
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
    let opened = MULTIPATH.open(&state, &user, &router).await?;
    let domain = opened.context().await?;
    let (action, policy) = known(opened, &domain, &query.name).await?;
    let planned = plan::multipath(&domain, policy.name(), enabled);
    Ok(planned_change(
        action,
        &domain,
        planned.map(|op| vec![op]),
        (&headers, &user),
    )
    .await)
}

/// `POST /ui/r/{router}/routing/policy/unpermit?name=&interface=`: takes the interface off
/// the policy and checks that no line permits it any more.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn unpermit(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<RowQuery>,
    headers: HeaderMap,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let opened = UNPERMIT.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let domain = opened.context().await?;
    let (action, policy) = known(opened, &domain, &query.name).await?;
    if policy.permit(&query.interface).is_none() {
        action.abandon("gone").await;
        return Ok(answer(gone(locale), None, locale));
    }
    let planned = match plan::permit(
        &domain,
        policy.name(),
        &PolicyPermit::new(&query.interface),
        false,
    ) {
        Ok(op) => op,
        Err(error) => {
            return Ok(planned_change(action, &domain, Err(error), (&headers, &user)).await);
        }
    };
    let name = policy.name().to_owned();
    let interface = query.interface.clone();
    let outcome = action
        .run_with(Risk::Write, async |changes, context| {
            let result = apply::apply(changes, context, &planned)
                .await
                .map_err(workflow_error)?;
            let lines = configured(context).await.map_err(workflow_error)?;
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
        .await;
    let shown = refreshed(&domain, (&router, &user), &headers, locale).await;
    Ok(answer(outcome, shown, locale))
}

/// `GET /ui/r/{router}/routing/policy/delete?name=`: asks for the policy's name.
///
/// # Errors
///
/// Answers 404 for a policy the router does not have, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn delete_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = DELETE.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let policy = find(&domain, query.name()).await.ok_or_else(missing)?;
    let dialog = confirmation(action.locale(), &router, policy.name());
    Ok(respond::in_dialog(errors::render(&dialog)))
}

/// `POST /ui/r/{router}/routing/policy/delete`: deletes the policy once its name is typed.
///
/// # Errors
///
/// Answers the dialog again (422) when the typed name does not match, and what the kit
/// answers when the router or the permission is missing.
pub(crate) async fn delete(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<TypedNameForm>,
) -> Result<Response, Answer> {
    let opened = DELETE.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let domain = opened.context().await?;
    let (action, policy) = match known(opened, &domain, form.name()).await {
        Ok(found) => found,
        Err(refused) => return Ok(respond::retarget(refused.into_response(), "#page-outcome")),
    };
    if !form.confirmed() {
        action.abandon("validation_failed").await;
        let mut dialog = confirmation(locale, &router, policy.name());
        dialog.set_error(tr(locale, keys::WEB_ADMIN_ERROR_CONFIRM, None));
        return Err(respond::in_dialog(respond::unprocessable(&dialog)).into());
    }
    let planned = plan::remove(&domain, policy.name());
    let answered = planned_change(
        action,
        &domain,
        planned.map(|op| vec![op]),
        (&headers, &user),
    )
    .await;
    Ok(respond::retarget(answered, "#page-outcome"))
}

/// The typed-name confirmation deleting the policy `name` of `router`.
fn confirmation(locale: Locale, router: &str, name: &str) -> TypedNameDialog {
    TypedNameDialog::new(
        fragment_shell(locale),
        format!("/ui/r/{router}/routing/policy/delete"),
        name,
        (
            keys::WEB_ROUTING_POLICY_DELETE_TITLE,
            keys::WEB_ROUTING_POLICY_DELETE_TEXT,
        ),
    )
}
