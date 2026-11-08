//! A router account's password: a management change whose dialog explains the fail-safe
//! timer and whose Apply confirms it, so the password never travels in a query string.
//!
//! The account kcc signs in with is refused before anything is sent: change that password
//! on the router, then the router's password in kcc.

use axum::{
    Form,
    extract::{Path, Query, State},
    response::Response,
};
use kcc_app::workflow::CliChangeRequest;
use kcc_catalog::Risk;
use kcc_domain::{DomainError, Result as DomainResult, RouterCtx, router_users};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    dialog::{Entry, SecretDialog, entry},
    reply::{unchanged, verified},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{self, Params, missing, unusable, with_query},
    page_kit::{
        action::{Action, Operation},
        change::Change,
        confirm::Confirmation,
        failure::plan_failure,
        family::Family,
        respond::Answer,
    },
    system_pages::shared::profile_login,
};

/// Setting a router account's password, audited as `web.router_user_password`.
const SET_PASSWORD: Operation = Operation::write(
    &router_users::DESCRIPTOR,
    "set_password",
    "web.router_user_password",
);

/// The dialog of the account `name` on `router`.
fn dialog(router: &str, name: &str, locale: Locale) -> SecretDialog {
    let post_to = with_query(
        &format!("/ui/r/{router}/system/users/password"),
        &[("name", name)],
    );
    SecretDialog::new(
        locale,
        (keys::WEB_SECRET_USER_TITLE, name),
        post_to,
        (keys::WEB_SECRET_NEW_PASSWORD, keys::WEB_SECRET_USER_HELP),
    )
    .management()
}

/// The refusal for the account kcc signs in with.
pub(crate) fn protected(locale: Locale) -> String {
    tr(locale, keys::WEB_SECRET_USER_PROTECTED, None)
}

/// `GET /ui/r/{router}/system/users/password?name=`: the dialog, or why the account kcc
/// signs in with cannot change its password here.
///
/// # Errors
///
/// Answers 404 for a missing name, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn password_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = SET_PASSWORD.open(&state, &user, &router).await?;
    let locale = action.locale();
    let shown = dialog(&router, name.as_str(), locale);
    if profile_login(&state, &user, &router).await.as_deref() == Some(name.as_str()) {
        return Ok(shown.refused(protected(locale)).show());
    }
    Ok(shown.show())
}

/// `POST /ui/r/{router}/system/users/password?name=`: sets the password typed twice in
/// the form body, confirmed by the dialog's Apply.
///
/// # Errors
///
/// Answers 404 for a missing or unknown account, the dialog with its error or the
/// refusal (422), and what the kit answers when the router or the permission is missing.
pub(crate) async fn password(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(mut form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = SET_PASSWORD.open(&state, &user, &router).await?;
    let locale = action.locale();
    let shown = dialog(&router, name.as_str(), locale);
    let login = profile_login(&state, &user, &router)
        .await
        .unwrap_or_default();
    if login == name.as_str() {
        action.abandon("protected_account").await;
        return Err(shown.refused(protected(locale)).refusal());
    }
    let confirmed = Confirmation::from_pairs(&form).confirmed();
    let secret = match entry(&mut form) {
        Entry::Keep => return Ok(unchanged(action).await),
        Entry::Mismatch => {
            action.abandon("validation_failed").await;
            return Err(shown.mismatch());
        }
        Entry::New(typed) => typed,
    };
    if !confirmed {
        action.abandon("confirmation_required").await;
        return Err(shown.secret_error(tr(locale, keys::WEB_SECRET_CONFIRM, None)));
    }
    let (known, domain) = account(action, name.as_str()).await?;
    let planned = router_users::plan_password(&domain, name.as_str(), &login, secret)
        .and_then(|operation| router_users::change_request(&operation));
    run(known, planned, shown).await
}

/// `action` with its router context, once the account `name` is known to exist there.
///
/// # Errors
///
/// Answers 404 for an unknown account and the failure when the router cannot be read;
/// both are audited.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn account<'call>(
    action: Action<'call>,
    name: &str,
) -> Result<(Action<'call>, RouterCtx), Answer> {
    let domain = action.context().await?;
    match router_users::read_users(&domain).await {
        Ok(users)
            if users
                .iter()
                .any(|found| found.name.as_deref() == Some(name)) =>
        {
            Ok((action, domain))
        }
        Ok(_) => {
            action.abandon("not_found").await;
            Err(missing())
        }
        Err(_) => {
            let locale = action.locale();
            action.abandon("unreachable").await;
            Err(unusable(locale, Family::Changes.unreachable()))
        }
    }
}

/// Runs a planned password change of a router account inside the fail-safe timer and
/// answers with the read-back's verdict; a refused plan comes back into `shown`.
///
/// # Errors
///
/// Answers the dialog with the refusal or the planning error (422).
// NOT cancel-safe: see `Action::run`.
pub(crate) async fn run(
    action: Action<'_>,
    planned: DomainResult<CliChangeRequest>,
    shown: SecretDialog,
) -> Result<Response, Answer> {
    let locale = action.locale();
    let request = match planned {
        Ok(request) => request,
        Err(DomainError::ProtectedAccount) => {
            action.abandon("protected_account").await;
            return Err(shown.refused(protected(locale)).refusal());
        }
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            return Err(shown.secret_error(failure.message().to_owned()));
        }
    };
    let outcome = verified(
        action.run(Risk::Management, Change::Cli(request)).await,
        locale,
        keys::WEB_INTERNET_PASSWORD,
    );
    Ok(net_change::answer(outcome, None, locale))
}
