//! The enrolment actions of the SSH section: SSH management switched and its port set,
//! the two enrolment steps (probe, then bootstrap or re-pin), revoke and disable.
//!
//! The steps run inline. Step 2 carries the Entware root password, which becomes a
//! `SecretString` at once, is moved into the one password session and is never shown
//! again: no answer and no audit entry carries it.

use askama::Template;
use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::entware_ssh::state::{DEFAULT_PORT, EnrolmentState};
use kcc_domain::entware::ssh::enrol;
use kcc_i18n::{bundle::tr, keys};

use super::{
    entware_change::switch,
    entware_ssh::store,
    entware_ssh_desk::{Desk, Doing},
    shared::{merged, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        confirm::Resubmit,
        context::fragment_shell,
        outcome::{Failure, Outcome},
        request::{missing, with_query},
        respond::{Answer, close_dialog},
    },
};

/// Which of the two enrolment flows a step belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// The first enrolment, or one again with the same host key.
    Bootstrap,
    /// The enrolment of a host key that replaced the pinned one.
    Repin,
}

impl Mode {
    /// The mode named `word`.
    pub(super) fn parse(word: Option<&str>) -> Option<Self> {
        match word {
            Some("bootstrap") => Some(Self::Bootstrap),
            Some("repin") => Some(Self::Repin),
            Some(_) | None => None,
        }
    }

    /// The step's path below the section.
    pub(super) const fn word(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Repin => "repin",
        }
    }

    /// The audit id of step 2.
    pub(super) const fn audited(self) -> &'static str {
        match self {
            Self::Bootstrap => "web.entware_ssh_bootstrap",
            Self::Repin => "web.entware_ssh_repin",
        }
    }
}

/// Step 2: the probed fingerprint shown again, its ticket, the password and the
/// confirmations.
#[derive(Template)]
#[template(path = "partials/system_entware_ssh_step.html")]
struct Step {
    /// Locale carrier.
    shell: Shell,
    /// Where step 2 posts.
    action: String,
    /// The flow.
    mode: Mode,
    /// The ticket nonce.
    nonce: String,
    /// The probed fingerprint.
    fingerprint: String,
    /// How to check the fingerprint out of band, localized with the SSH port.
    check: String,
    /// Whether an Active enrolment would be replaced.
    active: bool,
}

localized!(Step);

/// The section's path `tail` on `router`.
pub(super) fn path(router: &str, tail: &str) -> String {
    format!("/ui/r/{router}/system/entware/ssh/{tail}")
}

/// `POST .../entware/ssh/enabled?on=true|false`: switches SSH management, locally.
///
/// # Errors
///
/// What the desk answers, and 404 for another value.
// NOT cancel-safe: the record may be saved, and its audit entry queued, before the future is
// dropped.
pub(crate) async fn enabled(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let desk = Desk::open(&state, &user, &router, "web.entware_ssh_enabled").await?;
    let pairs = merged(query.as_deref(), form);
    let on = switch(&pairs)?;
    let word = if on { "true" } else { "false" };
    let again = Resubmit::new(
        with_query(&path(&router, "enabled"), &[("on", word)]),
        "#page-outcome",
    );
    if let Some(prompt) = desk.ask(&pairs, again, Doing::Local) {
        return Ok(prompt);
    }
    match enrol::set_enabled(desk.services(), &desk.caller(), on).await {
        Ok(_record) => {
            let key = if on {
                keys::WEB_SYSTEM_ENTWARE_SSH_ENABLED_ON
            } else {
                keys::WEB_SYSTEM_ENTWARE_SSH_ENABLED_OFF
            };
            let outcome = Outcome::done(tr(desk.locale(), key, None), false);
            Ok(desk.recorded(outcome, desk.refreshed().await).await)
        }
        Err(error) => Ok(desk.failed_unaudited(&error, None).await),
    }
}

/// `POST .../entware/ssh/port` with `port=1..65535`: sets the SSH port, locally.
///
/// # Errors
///
/// What the desk answers.
// NOT cancel-safe: the record may be saved, and its audit entry queued, before the future is
// dropped.
pub(crate) async fn port(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let desk = Desk::open(&state, &user, &router, "web.entware_ssh_port").await?;
    let pairs = merged(query.as_deref(), form);
    let typed = value(&pairs, "port").unwrap_or_default();
    let Some(number) = typed.parse::<u16>().ok().filter(|number| *number > 0) else {
        let rule = tr(desk.locale(), keys::WEB_SYSTEM_ENTWARE_SSH_PORT_RULE, None);
        return Ok(desk.refuse(Failure::new(rule, "validation_failed")).await);
    };
    let word = number.to_string();
    let again = Resubmit::new(
        with_query(&path(&router, "port"), &[("port", &word)]),
        "#page-outcome",
    );
    if let Some(prompt) = desk.ask(&pairs, again, Doing::Local) {
        return Ok(prompt);
    }
    match enrol::set_port(desk.services(), &desk.caller(), number).await {
        Ok(_record) => {
            let mut args = FluentArgs::new();
            args.set("port", word);
            let said = tr(
                desk.locale(),
                keys::WEB_SYSTEM_ENTWARE_SSH_PORT_SET,
                Some(&args),
            );
            Ok(desk
                .recorded(Outcome::done(said, false), desk.refreshed().await)
                .await)
        }
        Err(error) => Ok(desk.failed_unaudited(&error, None).await),
    }
}

/// `POST .../entware/ssh/probe?mode=bootstrap|repin`: step 1, the router's host key
/// fingerprint with its single-use ticket and how to check it; no password is asked yet.
///
/// The host key is read within the page's read bound, like the lists.
///
/// # Errors
///
/// What the desk answers, the busy or slow answer included, and 404 for another mode.
// NOT cancel-safe: see `enrol::probe`.
pub(crate) async fn probe(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let desk = Desk::open(&state, &user, &router, "web.entware_ssh_probe").await?;
    let pairs = merged(query.as_deref(), form);
    let mode = Mode::parse(value(&pairs, "mode")).ok_or_else(missing)?;
    let again = Resubmit::new(
        with_query(&path(&router, "probe"), &[("mode", mode.word())]),
        "#entware-ssh-step",
    );
    if let Some(prompt) = desk.ask(&pairs, again, Doing::Probe) {
        return Ok(prompt);
    }
    let domain = desk.context().await?;
    let record = store(&state).and_then(|records| records.load(&router).ok().flatten());
    let ticket = desk
        .read(enrol::probe(desk.services(), &domain, &desk.caller()))
        .await?;
    let mut args = FluentArgs::new();
    let port = record.as_ref().map_or(DEFAULT_PORT, |found| found.port);
    args.set("port", port.to_string());
    let step = Step {
        shell: fragment_shell(desk.locale()),
        action: path(&router, mode.word()),
        mode,
        nonce: ticket.nonce,
        fingerprint: ticket.fingerprint,
        check: tr(
            desk.locale(),
            keys::WEB_SYSTEM_ENTWARE_SSH_STEP_CHECK,
            Some(&args),
        ),
        active: record.is_some_and(|found| found.state == EnrolmentState::Active),
    };
    Ok(close_dialog(errors::render(&step)))
}

/// `POST .../entware/ssh/revoke`: removes kcc's key from the router, then forgets it.
///
/// # Errors
///
/// What the desk answers.
// NOT cancel-safe: see `enrol::revoke`.
pub(crate) async fn revoke(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let desk = Desk::open(&state, &user, &router, "web.entware_ssh_revoke").await?;
    let again = Resubmit::new(path(&router, "revoke"), "#page-outcome");
    if let Some(prompt) = desk.ask(&pairs, again, Doing::Change) {
        return Ok(prompt);
    }
    let domain = desk.context().await?;
    let outcome = enrol::revoke(desk.services(), &domain, &desk.caller()).await;
    let refreshed = desk.refreshed().await;
    Ok(match outcome {
        Ok(()) => {
            let said = tr(desk.locale(), keys::WEB_SYSTEM_ENTWARE_SSH_REVOKED, None);
            desk.answer(Outcome::done(said, false), None, refreshed)
        }
        Err(error) => desk.failed(&error, refreshed),
    })
}

/// `POST .../entware/ssh/disable`: forgets kcc's key and pin locally; the router keeps
/// kcc's key line.
///
/// # Errors
///
/// What the desk answers.
// NOT cancel-safe: see `enrol::disable`.
pub(crate) async fn disable(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let desk = Desk::open(&state, &user, &router, "web.entware_ssh_disable").await?;
    let again = Resubmit::new(path(&router, "disable"), "#page-outcome");
    if let Some(prompt) = desk.ask(&pairs, again, Doing::Local) {
        return Ok(prompt);
    }
    match enrol::disable(desk.services(), &desk.caller()).await {
        Ok(_disabled) => {
            let said = tr(desk.locale(), keys::WEB_SYSTEM_ENTWARE_SSH_DISABLED, None);
            Ok(desk.answer(Outcome::done(said, false), None, desk.refreshed().await))
        }
        Err(error) => Ok(desk.failed(&error, None)),
    }
}
