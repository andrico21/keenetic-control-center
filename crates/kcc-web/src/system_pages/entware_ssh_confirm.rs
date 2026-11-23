//! Step 2 of the enrolment: the probed fingerprint confirmed with the Entware root
//! password, for a first enrolment (bootstrap) or a changed host key (re-pin).
//!
//! The password becomes a `SecretString` at once, is moved into the one password session
//! and is never shown again: no answer and no audit entry carries it. Everything the
//! page checks is checked before anything is sent.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use kcc_app::entware_ssh::state::EnrolmentState;
use kcc_domain::entware::ssh::enrol::{self, Confirmation, Enrolled};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use secrecy::{ExposeSecret as _, SecretString};

use super::{
    entware_ssh::store,
    entware_ssh_desk::{Desk, Doing},
    entware_ssh_enrol::{Mode, path},
    shared::value,
};
use crate::{
    WebState,
    authz::CurrentUser,
    markup::Rendered,
    page::{Localize as _, Shell},
    page_kit::{
        confirm::Resubmit,
        context::fragment_shell,
        outcome::{Failure, Outcome},
        request::rendered,
        respond::Answer,
    },
};

/// The longest nonce or fingerprint step 2 accepts.
const MAX_TOKEN: usize = 128;

/// `POST .../entware/ssh/bootstrap`: step 2 of the first enrolment.
///
/// # Errors
///
/// What the desk answers.
// NOT cancel-safe: see `enrol::bootstrap`.
pub(crate) async fn bootstrap(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    Box::pin(confirm(&state, (&user, &router), form, Mode::Bootstrap)).await
}

/// `POST .../entware/ssh/repin`: step 2 of the enrolment of a changed host key.
///
/// # Errors
///
/// What the desk answers.
// NOT cancel-safe: see `enrol::repin`.
pub(crate) async fn repin(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    Box::pin(confirm(&state, (&user, &router), form, Mode::Repin)).await
}

/// Step 2 of `mode`: the ticket, the confirmed fingerprint and the password from the
/// form body (never from the query), checked before anything is sent.
///
/// The fingerprint must be confirmed, the password given, and an Active enrolment, which
/// the step demotes to Pending before the router is contacted, explicitly given up.
///
/// # Errors
///
/// What the desk answers.
// NOT cancel-safe: see `enrol::bootstrap`.
async fn confirm(
    state: &WebState,
    (user, router): (&CurrentUser, &str),
    form: Vec<(String, String)>,
    mode: Mode,
) -> Result<Response, Answer> {
    let desk = Desk::open(state, user, router, mode.audited()).await?;
    let (secret, pairs): (Vec<_>, Vec<_>) =
        form.into_iter().partition(|(name, _)| name == "password");
    let typed_password = secret
        .into_iter()
        .map(|(_, typed)| SecretString::from(typed))
        .next_back();
    let token = |name| {
        value(&pairs, name)
            .filter(|found| !found.is_empty() && found.len() <= MAX_TOKEN)
            .map(str::to_owned)
    };
    let (Some(nonce), Some(fingerprint)) = (token("nonce"), token("fingerprint")) else {
        return Ok(refused(
            &desk,
            keys::WEB_SYSTEM_ENTWARE_SSH_TICKET_INVALID,
            "validation_failed",
        )
        .await);
    };
    if value(&pairs, "fingerprint_confirmed") != Some("yes") {
        return Ok(refused(
            &desk,
            keys::WEB_SYSTEM_ENTWARE_SSH_UNCONFIRMED,
            "confirmation_required",
        )
        .await);
    }
    let Some(password) = typed_password.filter(|typed| !typed.expose_secret().trim().is_empty())
    else {
        return Ok(refused(
            &desk,
            keys::WEB_SYSTEM_ENTWARE_SSH_PASSWORD_MISSING,
            "validation_failed",
        )
        .await);
    };
    let active = store(state)
        .and_then(|records| records.load(router).ok().flatten())
        .is_some_and(|record| record.state == EnrolmentState::Active);
    if active && value(&pairs, "replace_active") != Some("yes") {
        return Ok(refused(
            &desk,
            keys::WEB_SYSTEM_ENTWARE_SSH_REPLACE_UNCONFIRMED,
            "confirmation_required",
        )
        .await);
    }
    let again = Resubmit::new(path(router, mode.word()), "#page-outcome")
        .with_include("#entware-ssh-confirm-form");
    if let Some(prompt) = desk.ask(&pairs, again, Doing::Change) {
        return Ok(prompt);
    }
    let domain = desk.context().await?;
    let confirmation = Confirmation::new(nonce, fingerprint, password);
    let caller = desk.caller();
    let outcome = match mode {
        Mode::Bootstrap => enrol::bootstrap(desk.services(), &domain, &caller, confirmation).await,
        Mode::Repin => enrol::repin(desk.services(), &domain, &caller, confirmation).await,
    };
    let refreshed = desk.refreshed().await;
    Ok(match outcome {
        Ok(enrolled) => enrolled_answer(&desk, mode, &enrolled, refreshed),
        Err(error) => desk.failed(&error, refreshed),
    })
}

/// The page's refusal `key` of step 2, audited as `audit`: nothing was sent.
// NOT cancel-safe: an abandoned append may still be written.
async fn refused(desk: &Desk<'_>, key: MessageKey, audit: &'static str) -> Response {
    desk.refuse(Failure::new(tr(desk.locale(), key, None), audit))
        .await
}

/// The answer to a completed step 2, naming the default password when it signed in.
fn enrolled_answer(
    desk: &Desk<'_>,
    mode: Mode,
    enrolled: &Enrolled,
    refreshed: Option<Rendered>,
) -> Response {
    let key = match mode {
        Mode::Bootstrap => keys::WEB_SYSTEM_ENTWARE_SSH_ENROLLED,
        Mode::Repin => keys::WEB_SYSTEM_ENTWARE_SSH_REPINNED,
    };
    let warning = enrolled
        .default_password_in_use
        .then(|| {
            rendered(&DefaultPassword {
                shell: fragment_shell(desk.locale()),
            })
        })
        .flatten();
    desk.answer(
        Outcome::done(tr(desk.locale(), key, None), false),
        warning,
        refreshed,
    )
}

/// The warning that the Entware root password is still the default one.
#[derive(Template)]
#[template(
    ext = "html",
    source = "<p class=\"notice\" data-tone=\"warning\" id=\"entware-ssh-default-password\">{{ t(keys::WEB_SYSTEM_ENTWARE_SSH_DEFAULT_PASSWORD) }}</p>"
)]
struct DefaultPassword {
    /// Locale carrier.
    shell: Shell,
}

localized!(DefaultPassword);
