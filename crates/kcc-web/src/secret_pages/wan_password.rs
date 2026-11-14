//! The password of a PPP internet connection (PPPoE, L2TP, PPTP).

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::wan;
use kcc_i18n::{keys, locale::Locale};
use kcc_rci::ObjectName;

use super::{
    dialog::{Entry, SecretDialog, entry},
    reply::{unchanged, verified},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::unusable,
    net_internet,
    net_pages::{Call, Tab},
    net_wan::{Kind, links},
    page_kit::{
        action::Operation,
        change::Change,
        failure::plan_failure,
        family::Family,
        request::{Params, missing, with_query},
        respond::{Answer, changed},
    },
};

/// Setting a connection's password, audited as `web.internet_password`.
const PASSWORD: Operation = Operation::write(&wan::DESCRIPTOR, "password", "web.internet_password");

/// The dialog of the connection `name` on `router`.
fn dialog(router: &str, name: &ObjectName, locale: Locale) -> SecretDialog {
    let post_to = with_query(
        &format!("/ui/r/{router}/internet/password"),
        &[("name", name.as_str())],
    );
    SecretDialog::new(
        locale,
        (keys::WEB_SECRET_WAN_TITLE, name.as_str()),
        post_to,
        (keys::WEB_SECRET_NEW_PASSWORD, keys::WEB_SECRET_WAN_HELP),
    )
}

/// `GET /ui/r/{router}/internet/password?name=`: the dialog; it never holds the stored
/// password.
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
    let action = PASSWORD.open(&state, &user, &router).await?;
    Ok(dialog(&router, &name, action.locale()).show())
}

/// `POST /ui/r/{router}/internet/password?name=`: sets the password typed twice in the
/// form body on a PPP connection.
///
/// # Errors
///
/// Answers 404 for a missing name or a connection that is not PPP, the dialog with its
/// error (422), and what the kit answers when the router or the permission is missing.
pub(crate) async fn password(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(mut form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = PASSWORD.open(&state, &user, &router).await?;
    let locale = action.locale();
    let shown = dialog(&router, &name, locale);
    let secret = match entry(&mut form) {
        Entry::Keep => return Ok(unchanged(action).await),
        Entry::Mismatch => {
            action.abandon("validation_failed").await;
            return Err(shown.mismatch());
        }
        Entry::New(typed) => typed,
    };
    let domain = action.context().await?;
    match links(&domain).await {
        Ok(found)
            if found
                .iter()
                .any(|link| link.id() == name.as_str() && link.kind().is_some_and(Kind::ppp)) => {}
        Ok(_) => {
            action.abandon("not_found").await;
            return Err(missing());
        }
        Err(_) => {
            action.abandon("unreachable").await;
            return Err(unusable(locale, Family::Changes.unreachable()));
        }
    }
    let planned = wan::plan_password(&domain, &name, secret)
        .and_then(|operation| Ok((wan::change_request(&name, &operation)?, operation.risk)));
    let (request, risk) = match planned {
        Ok(found) => found,
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            return Err(shown.secret_error(failure.message().to_owned()));
        }
    };
    let outcome = verified(
        action.run(risk, Change::Cli(request)).await,
        locale,
        keys::WEB_INTERNET_PASSWORD,
    );
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Internet);
    let refreshed = if outcome.succeeded() {
        net_internet::refreshed(call, &domain).await
    } else {
        None
    };
    Ok(changed(outcome, refreshed, None, locale))
}
