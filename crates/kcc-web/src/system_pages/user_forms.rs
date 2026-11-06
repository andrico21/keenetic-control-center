//! The router-account dialogs and their changes: add an account with its service tags,
//! and change the tags of one.
//!
//! Both are management changes: the dialog explains the fail-safe timer and its Apply
//! confirms; the server checks the confirmation again and, without it, asks with the
//! kit's dialog, which sends the request again with the submitted names in its query
//! string (names and tags are not secrets).
//!
//! Passwords: the domain cannot set a router-account password yet (its secret-safe write
//! is being added to `router_users` by another change). When `router_users::plan_password`
//! lands, the add dialog gets a `kit::secret_field`, and `create` appends that plan's
//! request to the same change; the password must never travel in the query string, so
//! that form keeps its own confirmation instead of the kit's resubmitted one.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use kcc_app::{permissions::Permission, workflow::CliChangeRequest};
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, DomainError, Result as DomainResult, RouterCtx, router_users};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    shared::{answer, merged, missing, shown_query, value, values, with_query},
    user_dialog::{Field, UserDialog, check},
    users::{Account, Viewer, accounts, offered_tags},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::{Confirmation, Resubmit},
        failure::plan_failure,
        family::Family,
        outcome::Outcome,
        respond::Answer,
    },
};

/// Adding an account, audited as `web.router_user_create`.
pub(crate) const CREATE: Operation = Operation::write(
    &router_users::DESCRIPTOR,
    "create",
    "web.router_user_create",
);

/// Changing an account's tags, audited as `web.router_user_tags`.
pub(crate) const SET_TAG: Operation =
    Operation::write(&router_users::DESCRIPTOR, "set_tag", "web.router_user_tags");

/// `POST /ui/r/{router}/system/users`: adds an account with its tags.
///
/// # Errors
///
/// Answers the dialog with its field error (422), and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn create(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = CREATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let offered = offered_tags(&domain.catalog);
    let name = value(&pairs, "name").unwrap_or_default().to_owned();
    let tags = values(&pairs, "tag");
    let dialog = UserDialog::base(locale, &offered)
        .adding(&router)
        .naming(&name)
        .checking(&tags);
    let problem = match check(&name, &tags, &offered) {
        Err(found) => Some(found),
        Ok(()) if find(&domain, &name).await.is_some() => {
            Some((Field::Name, keys::WEB_SYSTEM_USERS_NAME_TAKEN))
        }
        Ok(()) => None,
    };
    if let Some((field, message)) = problem {
        action.abandon("validation_failed").await;
        return Err(dialog.refused(field, tr(locale, message, None)));
    }
    let planned = router_users::plan_create(&domain, &name, &tags)
        .and_then(|operation| Ok((router_users::change_request(&operation)?, operation.risk)));
    let (request, risk) = match planned {
        Ok(found) => found,
        Err(error) => {
            action.abandon("validation_failed").await;
            return Err(dialog.refused(Field::Name, refusal_message(&error, locale)));
        }
    };
    let mut resubmitted = vec![("name", name.as_str())];
    resubmitted.extend(tags.iter().map(|tag| ("tag", *tag)));
    let resubmit = Resubmit::new(
        with_query(&format!("/ui/r/{router}/system/users"), &resubmitted),
        "#page-outcome",
    );
    if let Some(prompt) = action.confirm(risk, &Confirmation::from_pairs(&pairs), resubmit) {
        return Ok(prompt);
    }
    let outcome = action.run(risk, Change::Cli(request)).await;
    let refreshed = if outcome.succeeded() {
        Viewer::new(&user, &router, shown_query(&headers))
            .refreshed(&state, &domain)
            .await
    } else {
        None
    };
    Ok(answer(outcome, refreshed, locale))
}

/// `POST /ui/r/{router}/system/users/tags`: sets the tags of one account to the checked
/// ones; tags the catalog does not offer are left as they are.
///
/// # Errors
///
/// Answers 404 for an unknown account, the dialog with its error (422), and what the kit
/// answers when the router or the permission is missing.
pub(crate) async fn set_tags(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = SET_TAG.open(&state, &user, &router).await?;
    let locale = action.locale();
    let domain = action.context().await?;
    let offered = offered_tags(&domain.catalog);
    let name = value(&pairs, "name").unwrap_or_default().to_owned();
    let wanted = values(&pairs, "tag");
    let Some(account) = find(&domain, &name).await else {
        action.abandon("not_found").await;
        return Err(missing());
    };
    let dialog = UserDialog::base(locale, &offered)
        .tagging(&router, &account)
        .checking(&wanted);
    if let Err((field, message)) = check(&name, &wanted, &offered) {
        action.abandon("validation_failed").await;
        return Err(dialog.refused(field, tr(locale, message, None)));
    }
    let changes: Vec<(&str, bool)> = offered
        .iter()
        .map(String::as_str)
        .filter_map(|tag| {
            let wants = wanted.contains(&tag);
            (account.tags().iter().any(|held| held == tag) != wants).then_some((tag, wants))
        })
        .collect();
    if changes.is_empty() {
        action.abandon("unchanged").await;
        let headline = tr(locale, keys::WEB_SYSTEM_UNCHANGED, None);
        return Ok(answer(Outcome::info(headline, "unchanged"), None, locale));
    }
    let request = match plan_tags(&domain, &name, &changes) {
        Ok(found) => found,
        Err(error) => {
            action.abandon("validation_failed").await;
            return Err(dialog.refused(Field::Tags, refusal_message(&error, locale)));
        }
    };
    let mut resubmitted = vec![("name", name.as_str())];
    resubmitted.extend(wanted.iter().map(|tag| ("tag", *tag)));
    let resubmit = Resubmit::new(
        with_query(&format!("/ui/r/{router}/system/users/tags"), &resubmitted),
        "#page-outcome",
    );
    let confirmation = Confirmation::from_pairs(&pairs);
    if let Some(prompt) = action.confirm(Risk::Management, &confirmation, resubmit) {
        return Ok(prompt);
    }
    let outcome = action.run(Risk::Management, Change::Cli(request)).await;
    let refreshed = if outcome.succeeded() {
        Viewer::new(&user, &router, shown_query(&headers))
            .refreshed(&state, &domain)
            .await
    } else {
        None
    };
    Ok(answer(outcome, refreshed, locale))
}

/// The account `name` of the router of `domain`.
// cancel-safe: reads only.
pub(crate) async fn find(domain: &RouterCtx, name: &str) -> Option<Account> {
    accounts(domain, None)
        .await
        .ok()?
        .into_iter()
        .find(|account| account.name() == name)
}

/// One change setting `changes` (tag, wanted) on the account `name`: the account's
/// context once, then each tag added or removed.
///
/// # Errors
///
/// Returns the domain's refusal, such as removing `cli` from `admin`.
fn plan_tags(
    domain: &RouterCtx,
    name: &str,
    changes: &[(&str, bool)],
) -> DomainResult<CliChangeRequest> {
    let mut requests = Vec::new();
    for (tag, wanted) in changes {
        let operation = router_users::plan_tag(domain, name, tag, *wanted)?;
        let skip = usize::from(!requests.is_empty());
        requests.extend(operation.requests.into_iter().skip(skip));
    }
    router_users::change_request(&ChangeOp::new(
        requests,
        Vec::new(),
        Risk::Management,
        Permission::ManageUsers,
        false,
    ))
}

/// The message of a domain refusal: the protected-account rule in its own words, else
/// the catalog's findings.
pub(crate) fn refusal_message(error: &DomainError, locale: Locale) -> String {
    match error {
        DomainError::ProtectedAccount => tr(locale, keys::WEB_SYSTEM_USERS_PROTECTED, None),
        DomainError::Rci(_)
        | DomainError::InvalidResponse
        | DomainError::Validation { issues: _ }
        | DomainError::ConfirmationMismatch
        | DomainError::StaticLeaseOutsidePool
        | DomainError::StaticLeaseAddressInUse
        | DomainError::InvalidCliToken
        | DomainError::ConfirmationRequired
        | DomainError::PermissionDenied
        | _ => plan_failure(Family::Changes, locale, error)
            .message()
            .to_owned(),
    }
}
