//! The router-account dialogs and their changes: add an account with its service tags,
//! and change the tags of one.
//!
//! Both are management changes: the dialog explains the fail-safe timer and its Apply
//! confirms; the server checks the confirmation again and, without it, asks with the
//! kit's dialog, which sends the request again with the submitted names in its query
//! string (names and tags are not secrets).
//!
//! The add dialog also takes an optional password, typed twice into write-only fields
//! (`kit::secret_field`); `create` appends the domain's protected password write to the
//! same change. A password never travels in a query string: a request carrying one must
//! already hold the dialog's confirmation, or nothing is sent.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, DomainError, Result as DomainResult, RouterCtx, router_users};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use secrecy::SecretString;

use super::{
    shared::{merged, profile_login, value, values},
    user_answers::UserForm,
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
        request::{Params, missing, shown_query, with_query},
        respond::{Answer, changed},
        submit::{Invalid, Planned, Submission},
    },
    secret_pages::dialog::{Entry, entry},
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
    Form(mut form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let typed = entry(&mut form);
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
    let confirmation = Confirmation::from_pairs(&pairs);
    let password = match typed {
        Entry::Keep => Ok(None),
        Entry::New(secret) if confirmation.confirmed() => Ok(Some(secret)),
        Entry::New(_) => {
            action.abandon("confirmation_required").await;
            let text = tr(locale, keys::WEB_SECRET_CONFIRM, None);
            return Err(dialog.refused(Field::Password, text));
        }
        Entry::Mismatch => Err((Field::Password, keys::WEB_SECRET_MISMATCH)),
    };
    let checked = match password.and_then(|kept| check(&name, &tags, &offered).map(|()| kept)) {
        Ok(_) if find(&domain, &name).await.is_some() => {
            Err((Field::Name, keys::WEB_SYSTEM_USERS_NAME_TAKEN))
        }
        found @ (Ok(_) | Err(_)) => found,
    };
    let login = profile_login(&state, &user, &router)
        .await
        .unwrap_or_default();
    let mut resubmitted = vec![("name", name.as_str())];
    resubmitted.extend(tags.iter().map(|tag| ("tag", *tag)));
    let resubmit = Resubmit::new(
        with_query(&format!("/ui/r/{router}/system/users"), &resubmitted),
        "#page-outcome",
    );
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    Ok(Submission::new(
        action,
        &Params::of(pairs.clone()),
        UserForm::new(dialog, Field::Name),
        resubmit,
    )
    .submit(
        |_params| checked.map_err(|(field, rule)| Invalid::at(field.name(), rule)),
        async |typed_password, ctx| {
            let protected = typed_password.map(|secret| (secret, login.as_str()));
            plan_account(ctx, (&name, &tags), protected)
        },
        async |ctx| viewer.refreshed(&state, ctx).await,
    )
    .await)
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
    let checked = check(&name, &wanted, &offered);
    let changes: Vec<(&str, bool)> = offered
        .iter()
        .map(String::as_str)
        .filter_map(|tag| {
            let wants = wanted.contains(&tag);
            (account.tags().iter().any(|held| held == tag) != wants).then_some((tag, wants))
        })
        .collect();
    if checked.is_ok() && changes.is_empty() {
        action.abandon("unchanged").await;
        let headline = tr(locale, keys::WEB_SYSTEM_UNCHANGED, None);
        return Ok(changed(
            Outcome::info(headline, "unchanged"),
            None,
            None,
            locale,
        ));
    }
    let mut resubmitted = vec![("name", name.as_str())];
    resubmitted.extend(wanted.iter().map(|tag| ("tag", *tag)));
    let resubmit = Resubmit::new(
        with_query(&format!("/ui/r/{router}/system/users/tags"), &resubmitted),
        "#page-outcome",
    );
    let viewer = Viewer::new(&user, &router, shown_query(&headers));
    Ok(Submission::new(
        action,
        &Params::of(pairs.clone()),
        UserForm::new(dialog, Field::Tags),
        resubmit,
    )
    .submit(
        |_params| checked.map_err(|(field, rule)| Invalid::at(field.name(), rule)),
        async |(), ctx| plan_tags(ctx, &name, &changes),
        async |ctx| viewer.refreshed(&state, ctx).await,
    )
    .await)
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

/// One change adding the account `name` with `tags` and, when typed, its password.
///
/// The password comes with the login kcc signs in with, which the domain refuses; its
/// protected write joins the same change, with its read-back.
///
/// # Errors
///
/// Returns the domain's refusal or the catalog's findings.
fn plan_account(
    domain: &RouterCtx,
    (name, tags): (&str, &[&str]),
    password: Option<(SecretString, &str)>,
) -> DomainResult<Planned> {
    let created = router_users::plan_create(domain, name, tags)?;
    let Some((secret, login)) = password else {
        let request = router_users::change_request(&created)?;
        return Ok(Planned::of(&[created], Change::Cli(request)));
    };
    let protected = router_users::plan_password(domain, name, login, secret)?;
    let risk = created.risk.max(protected.risk);
    let mut requests = created.requests;
    requests.extend(protected.requests.into_iter().skip(1));
    let operation = ChangeOp::new(
        requests,
        protected.verify,
        risk,
        protected.permission,
        false,
    );
    let request = router_users::change_request(&operation)?;
    Ok(Planned::of(&[operation], Change::Cli(request)))
}

/// One change setting `changes` (tag, wanted) on the account `name`: the account's
/// context once, then each tag added or removed.
///
/// # Errors
///
/// Returns the domain's refusal, such as removing `cli` from `admin`.
fn plan_tags(domain: &RouterCtx, name: &str, changes: &[(&str, bool)]) -> DomainResult<Planned> {
    let mut requests = Vec::new();
    for (tag, wanted) in changes {
        let operation = router_users::plan_tag(domain, name, tag, *wanted)?;
        let skip = usize::from(!requests.is_empty());
        requests.extend(operation.requests.into_iter().skip(skip));
    }
    let operation = ChangeOp::new(
        requests,
        Vec::new(),
        Risk::Management,
        Permission::ManageUsers,
        false,
    );
    let request = router_users::change_request(&operation)?;
    Ok(Planned::of(&[operation], Change::Cli(request)))
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
