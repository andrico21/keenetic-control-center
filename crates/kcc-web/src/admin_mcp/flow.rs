//! Carries a planned change to the running listeners.
//!
//! The password comes first when the change reduces safety, then a live apply or a
//! restart in the background, each audited as `web.mcp_settings` with the changed key
//! names and the restarted listeners.

extern crate alloc;

use alloc::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use kcc_app::{
    accounts::Authentication,
    mcp_settings::{Candidate, ListenerKind},
};
use kcc_i18n::{bundle::tr, keys};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use tokio::task::spawn_blocking;

use super::{
    Attached, Posted, Progress,
    messages::{Said, label},
    page::deadline,
    reply,
    status::Status,
};
use crate::{
    WebState,
    admin::{McpChange, mcp_control::McpRefusal},
    admin_shared::Timestamp,
    authz::CurrentUser,
    errors,
    page_kit::{
        audit::Record,
        context::fragment_shell,
        respond::{self, Answer},
    },
};

/// The audit action of every change of the page.
pub(crate) const ACTION: &str = "web.mcp_settings";

/// Appends the page's audit record with `params` ending as `outcome`.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn audit(state: &WebState, user: &CurrentUser, params: Value, outcome: &str) {
    Record::new(ACTION, "mcp".to_owned())
        .with_params(params)
        .append(state, user, outcome)
        .await;
}

/// The audited facts of `candidate`: the changed key names and the listeners it restarts.
fn params(candidate: &Candidate) -> Value {
    let restarted: Vec<&str> = candidate.restart().iter().map(|kind| name(*kind)).collect();
    let changed: Vec<&str> = candidate.changed().iter().map(|key| key.as_str()).collect();
    json!({ "changed": changed, "restarted": restarted })
}

/// The audited name of `kind`.
pub(crate) const fn name(kind: ListenerKind) -> &'static str {
    match kind {
        ListenerKind::Main => "main",
        ListenerKind::Dedicated | _ => "dedicated",
    }
}

/// Hands `candidate` to the running listeners once the password, when the change reduces
/// safety, is right.
// NOT cancel-safe: dropped after the hand-over, the change runs on unaudited.
pub(crate) async fn submit(
    state: &WebState,
    user: &CurrentUser,
    (attached, candidate): (Arc<Attached>, Candidate),
    posted: Posted<'_>,
) -> Response {
    let locale = user.locale();
    let params = params(&candidate);
    if !candidate.safety_reducing().is_empty() {
        let reduces: Vec<String> = candidate
            .safety_reducing()
            .iter()
            .map(|key| tr(locale, label(*key), None))
            .collect();
        let text = Said::new(
            locale,
            keys::WEB_ADMIN_MCP_CONFIRM_TEXT,
            Some(("what", reduces.join(", "))),
        )
        .text()
        .to_owned();
        let Some(password) = posted.password else {
            return reply::dialog(locale, (posted.to, posted.pairs), text, None);
        };
        let refusal = match confirmed(state, user, password).await {
            Ok(checked) => checked,
            Err(answer) => return answer.into_response(),
        };
        if let Some((said, outcome)) = refusal {
            audit(state, user, params, outcome).await;
            return reply::dialog(locale, (posted.to, posted.pairs), text, Some(said));
        }
    }
    let answer = if candidate.restart().is_empty() {
        let result = attached.control().apply_live(candidate).await;
        audit(state, user, params, outcome(result)).await;
        match result {
            Ok(()) => {
                let said = Said::new(locale, keys::WEB_ADMIN_MCP_SAVED, None);
                reply::notice(state, user, (said, "success"), StatusCode::OK).await
            }
            Err(refusal) => {
                let said = Said::refusal(locale, refusal);
                reply::notice(state, user, (said, "error"), StatusCode::CONFLICT).await
            }
        }
    } else {
        let kinds = candidate.restart().to_vec();
        let change = attached.control().restart(candidate);
        in_background(state, user, attached, (kinds, change, params)).await
    };
    if posted.password.is_some() {
        respond::close_dialog(answer)
    } else {
        answer
    }
}

/// Awaits `change`, which restarts `kinds`, in a background task; the restart status.
///
/// The change is recorded as the page's restart in progress; the task audits `params`
/// with its outcome and then records how it ended, and the status polls until then.
// NOT cancel-safe: dropped after the hand-over, the change and its audit run on.
pub(crate) async fn in_background(
    state: &WebState,
    user: &CurrentUser,
    attached: Arc<Attached>,
    (kinds, change, params): (Vec<ListenerKind>, McpChange, Value),
) -> Response {
    let locale = user.locale();
    let progress = Progress::Restarting(kinds);
    attached.set_progress(progress.clone());
    let (state_now, user_now) = (state.clone(), user.clone());
    drop(tokio::spawn(async move {
        let result = change.await;
        audit(&state_now, &user_now, params, outcome(result)).await;
        attached.set_progress(result.map_or_else(Progress::Refused, |()| Progress::Applied));
    }));
    reply::restarting(state, user, Status::new(locale, &progress, deadline(state))).await
}

/// The audit outcome of `result`.
pub(crate) const fn outcome(result: Result<(), McpRefusal>) -> &'static str {
    match result {
        Ok(()) => "success",
        Err(refusal) => refusal.code(),
    }
}

/// Checks `password` for the signed-in account: `None` when right, otherwise the
/// refusal and its audit outcome. A wrong password counts toward the sign-in lockout; a
/// lockout ends no session.
///
/// # Errors
///
/// The error page when the accounts cannot be read.
// cancel-safe: the check runs whole on a blocking thread; dropped, only its answer is lost.
pub(crate) async fn confirmed(
    state: &WebState,
    user: &CurrentUser,
    password: &SecretString,
) -> Result<Option<(Said, &'static str)>, Answer> {
    let locale = user.locale();
    let accounts = Arc::clone(state.accounts());
    let username = user.username().to_owned();
    let typed = SecretString::from(password.expose_secret().to_owned());
    let checked = spawn_blocking(move || accounts.authenticate(&username, &typed)).await;
    match checked {
        Ok(Ok(Authentication::Authenticated { role: _, locale: _ })) => Ok(None),
        Ok(Ok(Authentication::Locked { until })) => {
            let time = Timestamp::at(until, locale)
                .map_or_else(|| until.to_string(), |at| at.text().to_owned());
            let said = Said::new(
                locale,
                keys::WEB_ADMIN_MCP_CONFIRM_LOCKED,
                Some(("time", time)),
            );
            Ok(Some((said, "locked")))
        }
        Ok(Ok(Authentication::Invalid | Authentication::Disabled | _)) => {
            let said = Said::new(locale, keys::WEB_ADMIN_MCP_CONFIRM_WRONG, None);
            Ok(Some((said, "wrong_password")))
        }
        Ok(Err(error)) => Err(errors::internal(&error, fragment_shell(locale)).into()),
        Err(error) => Err(errors::internal(&error, fragment_shell(locale)).into()),
    }
}
