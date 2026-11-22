//! The guided Entware setup of the Entware page.
//!
//! Setting Entware up runs root scripts from the chosen drive (or the internal storage),
//! so it is destructive and needs the router name typed. It runs as a job that holds the
//! router's change lease: it installs the missing components (the router restarts), sends
//! the installer of the router's architecture, follows the installer's log lines and reads
//! the drive setting back. The job panel follows it through the job stream; it ends with
//! the configuration unsaved and offers the save, which the job never does itself.

use alloc::sync::Arc;

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    audit::{Actor, ActorKind},
    jobs::JobError,
    permissions::Permission,
};
use kcc_catalog::Risk;
use kcc_domain::entware::{
    models::{Installer, Possibility},
    setup::{self, DriveChoice, SetupError, SetupRequest},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde_json::Value;

use super::{
    jobs::JobPanel,
    shared::{merged, value},
};
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
        request::{missing, with_query},
        respond::{Answer, close_dialog},
    },
};

/// The setup, audited as `web.entware_setup`.
pub(crate) const SETUP: Operation = Operation::planned(
    "opkg disk",
    (Permission::Destructive, Risk::Destructive),
    "web.entware_setup",
);

/// The `drive` value that chooses the router's internal storage.
const INTERNAL: &str = "internal";

/// The installer chosen in the form: none (the router's architecture decides), or one of
/// the closed installer table.
///
/// # Errors
///
/// Answers 404 for any other value.
fn installer(pairs: &[(String, String)]) -> Result<Option<Installer>, Answer> {
    match value(pairs, "installer").unwrap_or_default() {
        "" => Ok(None),
        "aarch64" => Ok(Some(Installer::Aarch64)),
        "mipsel" => Ok(Some(Installer::Mipsel)),
        "mips" => Ok(Some(Installer::Mips)),
        _ => Err(missing()),
    }
}

/// Why the setup did not start, in the user's words.
fn setup_failure(error: &SetupError, locale: Locale) -> Failure {
    let said = |key, audit| Failure::new(tr(locale, key, None), audit);
    match error {
        SetupError::Domain(domain) => plan_failure(Family::Changes, locale, domain),
        SetupError::Registry(_) => Failure::forbidden(locale),
        SetupError::NotPossible(Possibility::UnsupportedArch(arch)) => {
            let mut args = FluentArgs::new();
            args.set("name", arch.clone());
            let text = tr(locale, keys::WEB_SYSTEM_ENTWARE_NO_ARCH, Some(&args));
            Failure::new(text, "not_possible")
        }
        SetupError::NotPossible(_) => said(keys::WEB_SYSTEM_ENTWARE_NO_USB, "not_possible"),
        SetupError::Unsaved => said(keys::WEB_SYSTEM_ENTWARE_UNSAVED, "unsaved"),
        SetupError::FailSafeActive => said(keys::WEB_SYSTEM_ENTWARE_FAIL_SAFE, "fail_safe_active"),
        SetupError::InstallerRequired => said(
            keys::WEB_SYSTEM_ENTWARE_INSTALLER_REQUIRED,
            "validation_failed",
        ),
        SetupError::InstallerMismatch(_) => said(
            keys::WEB_SYSTEM_ENTWARE_INSTALLER_MISMATCH,
            "validation_failed",
        ),
        SetupError::DriveNotEligible => said(
            keys::WEB_SYSTEM_ENTWARE_DRIVE_NOT_ELIGIBLE,
            "validation_failed",
        ),
        SetupError::DiskAlreadySet => said(keys::WEB_SYSTEM_ENTWARE_ALREADY_SET, "already_set"),
        SetupError::ComponentMissing {
            component: _,
            title,
        } => {
            let mut args = FluentArgs::new();
            args.set("name", (*title).to_owned());
            let text = tr(
                locale,
                keys::WEB_SYSTEM_ENTWARE_COMPONENT_MISSING,
                Some(&args),
            );
            Failure::new(text, "component_missing")
        }
        SetupError::Job(JobError::RouterBusy { router: _ }) => {
            said(keys::WEB_SYSTEM_JOB_BUSY, "busy")
        }
        SetupError::ConfirmationRequired | SetupError::Job(_) | _ => {
            tracing::error!(%error, "Entware setup did not start");
            said(Family::Changes.failed(), "failed")
        }
    }
}

/// `POST /ui/r/{router}/system/entware/setup`: asks for the router name, then starts the
/// setup job and answers with its panel.
///
/// The form sends `drive=<disk argument>|internal` and, on a MIPS router,
/// `installer=mipsel|mips`.
///
/// # Errors
///
/// Answers 404 for an installer outside the table, and what the kit answers when the
/// router or the permission is missing.
// NOT cancel-safe: the setup job (which may restart the router) may be started, and its audit
// entry queued, before the future is dropped.
pub(crate) async fn setup(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = SETUP.open(&state, &user, &router).await?;
    let installer = installer(&pairs)?;
    let locale = action.locale();
    let record = Record::on_router("web.entware_setup", &router, "opkg disk".to_owned());
    let chosen = value(&pairs, "drive").unwrap_or_default().to_owned();
    let drive = match chosen.as_str() {
        "" => {
            let failure = Failure::new(
                tr(locale, keys::WEB_SYSTEM_ENTWARE_DRIVE_NOT_ELIGIBLE, None),
                "validation_failed",
            );
            action.abandon(failure.audit()).await;
            return Ok(Outcome::failed(failure).render(locale));
        }
        INTERNAL => DriveChoice::InternalStorage,
        other => DriveChoice::Media(other.to_owned()),
    };
    let word = value(&pairs, "installer").unwrap_or_default();
    let again = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/system/entware/setup"),
            &[("drive", &chosen), ("installer", word)],
        ),
        "#page-outcome",
    );
    let confirmation = Confirmation::from_pairs(&pairs);
    if let Some(prompt) = action.confirm(Stakes::new(Risk::Destructive), &confirmation, again) {
        return Ok(prompt);
    }
    let domain = action.context().await?;
    let Some((jobs, fleet)) = state.advanced().jobs().cloned().zip(state.fleet()) else {
        let failure = Failure::new(
            tr(locale, keys::WEB_EXPLORER_JOBS_UNAVAILABLE, None),
            "failed",
        );
        record.append(&state, &user, failure.audit()).await;
        return Ok(close_dialog(Outcome::failed(failure).render(locale)));
    };
    let actor = Actor::new(ActorKind::Web, user.username().to_owned());
    let changes = match fleet
        .workflow()
        .begin(&router, actor.clone(), user.role(), false)
        .await
    {
        Ok(changes) => changes,
        Err(error) => {
            let failure = workflow_failure(Family::Changes, locale, &error);
            record.append(&state, &user, failure.audit()).await;
            return Ok(close_dialog(Outcome::failed(failure).render(locale)));
        }
    };
    let events = jobs.subscribe();
    let started = Box::pin(setup::start(
        &jobs,
        Arc::clone(fleet.registry()),
        Arc::clone(fleet.workflow()),
        router.clone(),
        actor,
        user.role(),
        changes,
        &domain.catalog,
        SetupRequest::new(drive, installer, true),
    ))
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
            Ok(close_dialog(
                JobPanel::new(locale, &router, id)
                    .titled(keys::WEB_SYSTEM_ENTWARE_SETUP_JOB)
                    .unstoppable()
                    .answer(),
            ))
        }
        Err(error) => {
            let failure = setup_failure(&error, locale);
            record.append(&state, &user, failure.audit()).await;
            Ok(close_dialog(Outcome::failed(failure).render(locale)))
        }
    }
}

/// A setup job's progress as one localized line, and whether it is the last one, which
/// ends with the configuration unsaved.
pub(crate) fn step_line(progress: &Value, locale: Locale) -> Option<(String, bool)> {
    let step = progress.get("step").and_then(Value::as_str)?;
    let installer_step = progress.get("installer_step").and_then(Value::as_u64);
    let said = |key| tr(locale, key, None);
    match (step, installer_step) {
        ("components", _) => Some((said(keys::WEB_SYSTEM_ENTWARE_STEP_COMPONENTS), false)),
        ("install", _) => Some((said(keys::WEB_SYSTEM_ENTWARE_STEP_INSTALL), false)),
        ("verify", Some(number)) => {
            let mut args = FluentArgs::new();
            args.set("value", number);
            let text = tr(locale, keys::WEB_SYSTEM_ENTWARE_STEP_VERIFY, Some(&args));
            Some((text, false))
        }
        ("verify", None) => Some((said(keys::WEB_SYSTEM_ENTWARE_STEP_WAIT), false)),
        ("read_back", _) => Some((said(keys::WEB_SYSTEM_ENTWARE_STEP_READ_BACK), false)),
        ("done", _) => {
            let unsaved = progress.get("unsaved").and_then(Value::as_bool) == Some(true);
            Some((said(keys::WEB_SYSTEM_ENTWARE_STEP_DONE), unsaved))
        }
        _ => None,
    }
}
