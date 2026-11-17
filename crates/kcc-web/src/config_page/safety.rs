//! Save, and the two ends of the fail-safe timer: keep the changes it guards (commit) or
//! roll them back, after which the router restores its saved configuration and restarts.
//!
//! All three run through the domain page kit on the configuration domain's operations:
//! Save and commit need `Save`, rollback `Destructive` and the router name typed. Commit
//! and rollback act only while the timer runs, Save only while it does not; otherwise
//! nothing is sent.

use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    permissions::Permission,
    workflow::{CliChangeRequest, CliCommand as ValidatedCli, WorkflowError},
};
use kcc_catalog::HttpMethod;
use kcc_domain::configuration;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::json;

use super::{
    confirm::{self, ConfirmDialog},
    page::Visit,
    status,
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::{Action, Operation},
        change::Applied,
        confirm::Gate,
        outcome::{Failure, Outcome},
        respond::{Answer, changed},
        submit::Planned,
    },
};

/// Save, audited as `web.config_save`.
const SAVE: Operation = Operation::write(&configuration::DESCRIPTOR, "save", "web.config_save");

/// Commit of the changes the fail-safe timer guards, audited as `web.config_commit`.
const COMMIT: Operation = Operation::write(
    &configuration::DESCRIPTOR,
    "fail_safe_commit",
    "web.config_commit",
);

/// Rollback of those changes, audited as `web.config_rollback`.
const ROLLBACK: Operation = Operation::write(
    &configuration::DESCRIPTOR,
    "fail_safe_rollback",
    "web.config_rollback",
);

/// The router command that rolls the guarded changes back.
const ROLLBACK_COMMAND: &str = "system configuration fail-safe rollback";

/// `POST /ui/r/{router}/config/save`: saves the running configuration.
///
/// # Errors
///
/// Answers why nothing was sent while the timer runs (keep or roll back the changes it
/// guards instead), and what the kit answers when the router or the permission is
/// missing.
// NOT cancel-safe: the save command may persist the configuration, and its audit entry be queued,
// before the future is dropped.
pub(crate) async fn save(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let opened = SAVE.open(&state, &user, &router).await?;
    let action = with_timer(opened, Timer::Idle).await?;
    let outcome = action
        .run_planned(Planned::described(|changes, _context| {
            Box::pin(async move {
                changes
                    .save()
                    .await
                    .map(|()| Applied::Done { unsaved: false })
            })
        }))
        .await;
    Ok(Visit::new(&state, &user, &router)
        .answer_status(outcome)
        .await)
}

/// `POST /ui/r/{router}/config/commit`: keeps the changes the fail-safe timer guards and
/// saves them.
///
/// # Errors
///
/// Answers why nothing was sent when the timer does not run, and what the kit answers
/// when the router or the permission is missing.
// NOT cancel-safe: the commit may persist the configuration, and its audit entry be queued, before
// the future is dropped.
pub(crate) async fn commit(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let opened = COMMIT.open(&state, &user, &router).await?;
    let action = with_timer(opened, Timer::Running).await?;
    let outcome = action
        .run_planned(Planned::described(|changes, _context| {
            Box::pin(async move {
                changes
                    .commit()
                    .await
                    .map(|()| Applied::Done { unsaved: false })
            })
        }))
        .await;
    Ok(Visit::new(&state, &user, &router)
        .answer_status(outcome)
        .await)
}

/// `POST /ui/r/{router}/config/rollback`: asks for the router name, then rolls the
/// changes the fail-safe timer guards back.
///
/// # Errors
///
/// Answers why nothing was sent when the timer does not run, and what the kit answers
/// when the router or the permission is missing.
// NOT cancel-safe: the rollback step may reach the router, and its audit entry be queued, before
// the future is dropped.
pub(crate) async fn rollback(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let opened = ROLLBACK.open(&state, &user, &router).await?;
    let action = with_timer(opened, Timer::Running).await?;
    let locale = action.locale();
    if let Gate::Ask { wrong_name } = confirm::gate(&pairs, &router) {
        let mut args = FluentArgs::new();
        args.set("router", router.clone());
        let words = (
            keys::WEB_CONFIG_ROLLBACK_TITLE,
            keys::WEB_CONFIG_ROLLBACK_TEXT,
            keys::WEB_CONFIG_ROLLBACK,
        );
        let action_url = format!("/ui/r/{router}/config/rollback");
        return Ok(ConfirmDialog::new(locale, action_url, (words, &args)).ask(wrong_name, &router));
    }
    let outcome = action
        .run_planned(Planned::described(|changes, context| {
            Box::pin(async move {
                let validated = context
                    .catalog
                    .validate(ROLLBACK_COMMAND, HttpMethod::Post, &json!({}))
                    .map_err(|issues| WorkflowError::CatalogValidation { issues })?;
                let request = CliChangeRequest::terminal(
                    vec![ValidatedCli::new(ROLLBACK_COMMAND.to_owned(), validated)?],
                    Permission::Destructive,
                    json!({ "operation": ROLLBACK_COMMAND }),
                );
                changes
                    .apply_recovery(request)
                    .await
                    .map(|result| Applied::Terminal(result.responses))
            })
        }))
        .await;
    Ok(changed(outcome, None, None, locale))
}

/// The state of the fail-safe timer an action needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Timer {
    /// Armed: commit and rollback end it.
    Running,
    /// Not armed: Save runs only then, as a running timer would still restore the
    /// configuration saved before the changes it guards.
    Idle,
}

/// `action` back when the router's fail-safe timer is in the state `needed`.
///
/// # Errors
///
/// Answers why nothing is sent: the timer is in the other state or the router did not
/// answer; the action is audited as abandoned (`not_armed`, `armed` or `unreachable`).
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, it reads once, and a refusal queues an audit entry that may be
// written after the future is dropped.
async fn with_timer(action: Action<'_>, needed: Timer) -> Result<Action<'_>, Answer> {
    let locale = action.locale();
    let domain = action.context().await?;
    let (message, audit) = match status::last_change(&domain).await {
        Ok(found) => {
            let running = found
                .fail_safe
                .as_ref()
                .and_then(|timer| timer.active)
                .unwrap_or(false);
            match (needed, running) {
                (Timer::Running, true) | (Timer::Idle, false) => return Ok(action),
                (Timer::Running, false) => (keys::WEB_CONFIG_NOT_ARMED, "not_armed"),
                (Timer::Idle, true) => (keys::WEB_CONFIG_SAVE_ARMED, "armed"),
            }
        }
        Err(unread) => (unread, "unreachable"),
    };
    action.abandon(audit).await;
    Err(refused(locale, Failure::new(tr(locale, message, None), audit)).into())
}

/// The answer to an action stopped by `failure`.
fn refused(locale: Locale, failure: Failure) -> Response {
    changed(Outcome::failed(failure), None, None, locale)
}
