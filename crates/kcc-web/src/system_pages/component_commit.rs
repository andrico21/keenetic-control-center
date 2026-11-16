//! The component commit of the components page.
//!
//! It applies the queued component changes and any firmware update the check found, and
//! restarts the router: a destructive change behind the typed router name. It runs as a
//! job that holds the router's change lease, reports committing, restarting and back
//! online, and reconnects to the router when it answers again; the job panel follows it.

use alloc::sync::Arc;

use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    audit::{Actor, ActorKind},
    jobs::JobError,
};
use kcc_catalog::Risk;
use kcc_domain::components::{self, CommitError};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::Value;

use super::jobs::JobPanel;
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        audit::Record,
        confirm::{Confirmation, Resubmit, Stakes},
        failure::{plan_failure, workflow_failure},
        family::Family,
        outcome::{Failure, Outcome},
        respond::Answer,
    },
};

/// The commit, audited as `web.components_commit`.
const COMMIT: Operation =
    Operation::write(&components::DESCRIPTOR, "commit", "web.components_commit");

/// `POST /ui/r/{router}/system/components/commit`: asks for the router name, then starts
/// the commit job and answers with its panel.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn commit(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = COMMIT.open(&state, &user, &router).await?;
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/system/components/commit"),
        "#page-outcome",
    );
    let confirmation = Confirmation::from_pairs(&pairs);
    if let Some(prompt) = action.confirm(Stakes::new(Risk::Destructive), &confirmation, resubmit) {
        return Ok(prompt);
    }
    let locale = action.locale();
    let domain = action.context().await?;
    let record = Record::on_router(
        "web.components_commit",
        &router,
        "components commit".to_owned(),
    );
    let Some((jobs, fleet)) = state.advanced().jobs().cloned().zip(state.fleet()) else {
        let failure = Failure::new(
            tr(locale, keys::WEB_EXPLORER_JOBS_UNAVAILABLE, None),
            "failed",
        );
        record.append(&state, &user, failure.audit()).await;
        return Ok(Outcome::failed(failure).render(locale));
    };
    let actor = Actor::new(ActorKind::Web, user.username().to_owned());
    let changes = match fleet
        .workflow()
        .begin(&router, actor, user.role(), false)
        .await
    {
        Ok(changes) => changes,
        Err(error) => {
            let failure = workflow_failure(Family::Changes, locale, &error);
            record.append(&state, &user, failure.audit()).await;
            return Ok(Outcome::failed(failure).render(locale));
        }
    };
    let events = jobs.subscribe();
    let started = components::start_commit_job(
        &jobs,
        Arc::clone(fleet.registry()),
        router.clone(),
        user.role(),
        changes,
        &domain.catalog,
        true,
    )
    .await;
    match started {
        Ok(id) => {
            state.advanced().feeds().follow(
                Arc::clone(&jobs),
                events,
                id.clone(),
                user.username().to_owned(),
            );
            record.append(&state, &user, "started").await;
            Ok(JobPanel::new(locale, &router, id)
                .titled(keys::WEB_SYSTEM_COMPONENTS_COMMIT_JOB)
                .unstoppable()
                .answer())
        }
        Err(error) => {
            let failure = commit_failure(&error, locale);
            record.append(&state, &user, failure.audit()).await;
            Ok(Outcome::failed(failure).render(locale))
        }
    }
}

/// Why the commit job did not start, in the user's words.
fn commit_failure(error: &CommitError, locale: Locale) -> Failure {
    match error {
        CommitError::Domain(domain) => plan_failure(Family::Changes, locale, domain),
        CommitError::Job(JobError::RouterBusy { router: _ }) => {
            Failure::new(tr(locale, keys::WEB_SYSTEM_JOB_BUSY, None), "busy")
        }
        CommitError::Registry(_) => Failure::new(
            tr(locale, Family::Changes.unreachable(), None),
            "unreachable",
        ),
        CommitError::ConfirmationRequired | CommitError::Job(_) | _ => {
            tracing::error!(%error, "component commit did not start");
            Failure::new(tr(locale, Family::Changes.failed(), None), "failed")
        }
    }
}

/// A commit job's progress as one localized line: committing, restarting, back.
pub(crate) fn phase_line(progress: &Value, locale: Locale) -> Option<String> {
    let after = progress
        .get("after_firmware")
        .and_then(Value::as_str)
        .filter(|title| !title.is_empty());
    match (progress.get("phase").and_then(Value::as_str)?, after) {
        ("committing", _) => Some(tr(locale, keys::WEB_SYSTEM_COMPONENTS_COMMITTING, None)),
        ("rebooting", _) => Some(tr(locale, keys::WEB_SYSTEM_COMPONENTS_REBOOTING, None)),
        ("completed", Some(title)) => {
            let mut args = FluentArgs::new();
            args.set("version", title.to_owned());
            Some(tr(locale, keys::WEB_SYSTEM_COMPONENTS_BACK, Some(&args)))
        }
        ("completed", None) => Some(tr(locale, keys::WEB_SYSTEM_COMPONENTS_BACK_PLAIN, None)),
        _ => None,
    }
}
