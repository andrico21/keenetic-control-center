//! `kcc entware setup`: the guided Entware installation as a job.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    jobs::{JobEvent, JobProgress, JobStatus},
    permissions::Permission,
};
use kcc_catalog::Risk;
use kcc_domain::entware::{
    models::{Installer, Possibility},
    setup::{self, DriveChoice, SetupError, SetupRequest},
};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::{Value, json};
use tokio::sync::broadcast::{Receiver, error::RecvError};

use super::{
    args_dom_entware::ArchChoice,
    context::Ctx,
    dom_jobs::runner,
    domains::Session,
    exit::{Exit, Failure, Outcome},
    output::Out,
    secret::confirm,
};

/// The longest disk argument the command line takes.
const DRIVE_LIMIT: usize = 128;

/// Starts the setup job on `drive` with the installer `arch` and follows it to its end.
///
/// The drive argument is checked before anything else; the role and the router id
/// confirmation before any router request.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the setup job keeps running in this process until it ends.
pub(crate) async fn setup(ctx: &Ctx, drive: String, arch: Option<ArchChoice>) -> Outcome {
    let choice = parse_drive(drive)?;
    let session = Session::open(ctx, Permission::Destructive).await?;
    let (services, target) = (session.services(), session.target());
    let confirmation = confirm(
        ctx.out(),
        ctx.globals(),
        Risk::Destructive,
        target.id(),
        false,
    );
    ctx.confirmed(services, target.id(), confirmation).await?;
    let changes = services
        .workflow()
        .begin(target.id(), ctx.principal().actor(), target.role(), false)
        .await?
        .with_request_id(ctx.request_id());
    let jobs = runner(ctx, services).await?;
    let events = jobs.subscribe();
    let installer = arch.map(|chosen| match chosen {
        ArchChoice::Aarch64 => Installer::Aarch64,
        ArchChoice::Mipsel => Installer::Mipsel,
        ArchChoice::Mips => Installer::Mips,
    });
    let job = setup::start(
        &jobs,
        Arc::clone(services.registry()),
        Arc::clone(services.workflow()),
        target.id().to_owned(),
        ctx.principal().actor(),
        target.role(),
        changes,
        &target.router().catalog,
        SetupRequest::new(choice, installer, true),
    )
    .await
    .map_err(|error| refusal(error, target.id()))?;
    let (status, lines) = follow(ctx.out(), &job, events).await;
    let message = jobs.get(&job).ok().and_then(|record| record.message);
    report(ctx.out(), (&job, target.id()), (status, lines, message))
}

/// The drive the command line names: `internal`, or a disk argument that is one router
/// CLI word ending in `:/`.
///
/// # Errors
///
/// Returns the validation failure (exit 4) for any other value; nothing is sent.
fn parse_drive(drive: String) -> Outcome<DriveChoice> {
    if drive == "internal" {
        return Ok(DriveChoice::InternalStorage);
    }
    let admitted = drive.len() <= DRIVE_LIMIT
        && drive.strip_suffix(":/").is_some_and(|device| {
            !device.is_empty()
                && !device.contains("..")
                && !device.chars().any(|character| {
                    character.is_whitespace()
                        || character.is_control()
                        || "'\"\\;|/:`$".contains(character)
                })
        });
    if admitted {
        Ok(DriveChoice::Media(drive))
    } else {
        Err(Failure::message(
            Exit::Validation,
            keys::CLI_ENTWARE_DRIVE_INVALID,
            &[],
        ))
    }
}

/// The failure of a setup refused before the job started.
fn refusal(error: SetupError, router: &str) -> Failure {
    let (exit, key): (Exit, MessageKey) = match error {
        SetupError::Registry(registry) => return Failure::from(registry),
        SetupError::Domain(domain) => return Failure::from(domain),
        SetupError::ComponentMissing { component, title } => {
            return Failure::message(
                Exit::Policy,
                keys::CLI_ENTWARE_COMPONENT_MISSING,
                &[("router", router), ("item", component), ("what", title)],
            );
        }
        SetupError::InstallerMismatch(installer) => {
            let value = serde_json::to_value(installer)
                .ok()
                .and_then(|name| name.as_str().map(str::to_owned))
                .unwrap_or_default();
            return Failure::message(
                Exit::Validation,
                keys::CLI_ENTWARE_ARCH_MISMATCH,
                &[("router", router), ("value", &value)],
            );
        }
        SetupError::NotPossible(Possibility::UnsupportedArch(arch)) => {
            return Failure::message(
                Exit::Policy,
                keys::CLI_ENTWARE_ARCH_UNSUPPORTED,
                &[("router", router), ("value", &arch)],
            );
        }
        SetupError::ConfirmationRequired => (Exit::Policy, keys::CLI_CONFIRM_MISSING),
        SetupError::NotPossible(_) => (Exit::Policy, keys::CLI_ENTWARE_NO_STORAGE),
        SetupError::Unsaved => (Exit::Conflict, keys::CLI_ENTWARE_UNSAVED),
        SetupError::FailSafeActive => (Exit::Conflict, keys::CLI_ENTWARE_FAIL_SAFE_ACTIVE),
        SetupError::InstallerRequired => (Exit::Validation, keys::CLI_ENTWARE_ARCH_REQUIRED),
        SetupError::DriveNotEligible => (Exit::Validation, keys::CLI_ENTWARE_DRIVE_NOT_ELIGIBLE),
        SetupError::DiskAlreadySet => (Exit::Conflict, keys::CLI_ENTWARE_DISK_SET),
        SetupError::Job(_) | _ => return Failure::text(Exit::Conflict, &error),
    };
    Failure::message(exit, key, &[("router", router)])
}

/// Notes each step of job `job` on stderr and collects its structured progress until the
/// job ends.
// cancel-safe: only receives events.
async fn follow(out: Out, job: &str, mut events: Receiver<JobEvent>) -> (JobStatus, Vec<Value>) {
    let mut lines = Vec::new();
    loop {
        match events.recv().await {
            Ok(event) if event.id == job => {
                if let Some(JobProgress::Structured(value)) = event.detail {
                    if let Some(key) = value.get("step").and_then(Value::as_str).and_then(step_key)
                    {
                        let step = out.tr(key, &[]);
                        let percent = event.progress.to_string();
                        out.note(&out.tr(
                            keys::CLI_ENTWARE_SETUP_PROGRESS,
                            &[("current", &percent), ("what", &step)],
                        ));
                    }
                    lines.push(value);
                }
                if event.status != JobStatus::Running {
                    return (event.status, lines);
                }
            }
            Ok(_) | Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => return (JobStatus::Interrupted, lines),
        }
    }
}

/// The localized name of a setup step, `None` for the final one.
fn step_key(step: &str) -> Option<MessageKey> {
    match step {
        "components" => Some(keys::CLI_ENTWARE_STEP_COMPONENTS),
        "install" => Some(keys::CLI_ENTWARE_STEP_INSTALL),
        "verify" => Some(keys::CLI_ENTWARE_STEP_VERIFY),
        "read_back" => Some(keys::CLI_ENTWARE_STEP_READ_BACK),
        _ => None,
    }
}

/// Prints the finished job `job` on `router`; a job that did not complete is a router
/// failure naming its reason.
///
/// # Errors
///
/// Returns output failures, or the router failure of an incomplete job.
fn report(
    out: Out,
    (job, router): (&str, &str),
    (status, lines, message): (JobStatus, Vec<Value>, Option<String>),
) -> Outcome {
    let completed = status == JobStatus::Completed;
    let human = if completed {
        out.tr(keys::CLI_ENTWARE_SETUP_DONE, &[("router", router)])
    } else {
        String::new()
    };
    out.emit(
        &json!({
            "job_id": job,
            "status": status,
            "progress": lines,
            "message": message,
            "unsaved": completed,
        }),
        &human,
    )?;
    if completed {
        Ok(())
    } else {
        Err(Failure::message(
            Exit::Router,
            keys::CLI_ENTWARE_SETUP_FAILED,
            &[("name", job), ("reason", message.as_deref().unwrap_or("-"))],
        ))
    }
}
