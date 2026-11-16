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
use kcc_catalog::Risk;
use kcc_domain::{ChangeOp, Result as DomainResult, RouterCtx, router_users};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::{
    dialog::{SecretDialog, entry},
    reply::{Secret, typed, unchanged},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::unusable,
    page_kit::{
        action::{Action, Operation},
        change::Change,
        confirm::{Confirmation, Resubmit},
        family::Family,
        request::{Params, missing, with_query},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
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
    let guarded = profile_login(&state, &user, &router)
        .await
        .and_then(|own| own.guard(name.as_str()));
    if guarded.is_err() {
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
    let own = match profile_login(&state, &user, &router).await {
        Ok(own) if own.guard(name.as_str()).is_ok() => own,
        Ok(_) | Err(_) => {
            action.abandon("protected_account").await;
            return Err(shown.refused(protected(locale)).refusal());
        }
    };
    let confirmed = Confirmation::from_pairs(&form).confirmed();
    let Some(checked) = typed(entry(&mut form)) else {
        return Ok(unchanged(action).await);
    };
    let (known, asked) =
        confirming(action, (checked.is_ok(), confirmed), (shown, name.as_str())).await?;
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/system/users/password"),
            &[("name", name.as_str())],
        ),
        "#page-outcome",
    );
    Ok(run(known, checked, (asked, resubmit), async |ctx, secret| {
        router_users::plan_password(ctx, name.as_str(), &own, secret)
    })
    .await)
}

/// `action` and `shown` back once a typed password may be sent.
///
/// A password typed twice (`typed`) needs the dialog's confirmation (`confirmed`) and an
/// account `name` the router has; a value that failed its check goes on to the
/// submission, which answers it.
///
/// # Errors
///
/// Answers `shown` asking for the confirmation, 404 for an unknown account and the failure
/// when the router cannot be read; each is audited.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn confirming<'call>(
    action: Action<'call>,
    (typed, confirmed): (bool, bool),
    (shown, name): (SecretDialog, &str),
) -> Result<(Action<'call>, SecretDialog), Answer> {
    if !typed {
        return Ok((action, shown));
    }
    if !confirmed {
        let locale = action.locale();
        action.abandon("confirmation_required").await;
        let asked = tr(locale, keys::WEB_SECRET_CONFIRM, None);
        return Err(shown.secret_error(asked));
    }
    let domain = action.context().await?;
    match router_users::read_users(&domain).await {
        Ok(users)
            if users
                .iter()
                .any(|found| found.name.as_deref() == Some(name)) =>
        {
            Ok((action, shown))
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

/// Runs the password change of a router account inside the fail-safe timer.
///
/// `plan` plans it with the `checked` values, the password typed twice among them; the
/// answer is the read-back's verdict, and a value that failed its check or a refused plan
/// comes back into `shown`. The dialog's own confirmation covers a management change; a
/// higher planned risk asks again, sending `resubmit`.
// NOT cancel-safe: see `Action::run_planned`.
pub(crate) async fn run<T, P>(
    action: Action<'_>,
    checked: Result<T, Invalid>,
    (shown, resubmit): (SecretDialog, Resubmit),
    plan: P,
) -> Response
where
    P: AsyncFnOnce(&RouterCtx, T) -> DomainResult<ChangeOp>,
{
    let params = Params::default();
    Submission::new(
        action,
        &params,
        Secret::new(shown, keys::WEB_INTERNET_PASSWORD),
        resubmit,
    )
    .confirmed_by_page(Risk::Management)
    .submit(
        |_params| checked,
        async |typed_values, ctx| {
            let operation = plan(ctx, typed_values).await?;
            let request = router_users::change_request(&operation)?;
            Ok(Planned::of(&[operation], Change::Cli(request)))
        },
        async |_ctx| None,
    )
    .await
}
