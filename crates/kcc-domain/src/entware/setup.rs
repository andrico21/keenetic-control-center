//! The guided Entware setup job.
//!
//! It installs the missing `opkg` and `ext` components, runs
//! `opkg disk <drive> <installer>`, proves the install from the log lines of this attempt
//! and a read-back of `opkg disk`, and ends with the configuration unsaved.

mod job;
mod preflight;
mod watch;

use alloc::sync::Arc;
use core::{fmt, result::Result as CoreResult, time::Duration};

use kcc_app::{
    audit::Actor,
    jobs::{JobError, JobRunner, JobTarget},
    permissions::{Permission, Role},
    registry::{RegistryError, RouterRegistry, authorize},
    workflow::{ChangeSet, ChangeWorkflow, CliChangeRequest},
};
use kcc_catalog::Catalog;
use serde::Serialize;

use super::models::{Installer, Possibility};
use crate::{DomainError, RouterCtx};

/// How often the job reads the router log while the installer runs.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The longest the job waits for the installer's success line.
pub const INSTALL_LIMIT: Duration = Duration::from_mins(15);

/// The installer's success line: the last of its five steps.
pub const INSTALLED_MARKER: &str = "[5/5] \"Entware\" installed!";

/// The final progress message: the job never saves the configuration.
pub const SAVE_NOTICE: &str =
    "Entware is installed; the configuration is unsaved: save it explicitly";

/// The drive Entware is installed on.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DriveChoice {
    /// An eligible drive, by its `disk_arg` (`<label>:/` or `<uuid>:/`).
    Media(String),
    /// The router's internal storage (`storage:/`), which the router calls untested.
    InternalStorage,
}

/// What the setup job installs and where.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the setup vocabulary the Web, MCP and CLI front ends use"
)]
pub struct SetupRequest {
    /// The drive.
    pub drive: DriveChoice,
    /// The installer; required when the router reports the ambiguous `mips` architecture.
    pub installer: Option<Installer>,
    /// The explicit confirmation of the destructive change.
    pub confirmed: bool,
}

impl SetupRequest {
    /// Creates a setup request.
    #[inline]
    #[must_use]
    pub const fn new(drive: DriveChoice, installer: Option<Installer>, confirmed: bool) -> Self {
        Self {
            drive,
            installer,
            confirmed,
        }
    }
}

/// A setup refused before any change reached the router.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the setup vocabulary the Web, MCP and CLI front ends use"
)]
pub enum SetupError {
    /// The caller did not confirm the destructive change.
    #[error("Entware setup requires explicit confirmation")]
    ConfirmationRequired,
    /// The role lacks `Destructive` on the router, or the router is unknown.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// The router cannot run Entware.
    #[error("the router cannot run Entware")]
    NotPossible(Possibility),
    /// The running configuration differs from the saved one.
    #[error("the router has unsaved changes: save or discard them first")]
    Unsaved,
    /// The router's fail-safe timer is armed.
    #[error("the router's fail-safe timer is armed")]
    FailSafeActive,
    /// The router reports `mips`, and no `mipsel` or `mips` installer was chosen.
    #[error("choose the mipsel or the mips installer")]
    InstallerRequired,
    /// The chosen installer does not match the router's architecture.
    #[error("the installer does not match the router's architecture")]
    InstallerMismatch(Installer),
    /// The drive is not one of the router's eligible drives.
    #[error("the drive is not eligible for Entware")]
    DriveNotEligible,
    /// `opkg disk` is already set.
    #[error("opkg disk is already set: remove it first")]
    DiskAlreadySet,
    /// `components list` does not offer a component Entware needs.
    #[error("the router does not offer the component {component} ({title})")]
    ComponentMissing {
        /// The component id.
        component: &'static str,
        /// The component's title in the router's interface.
        title: &'static str,
    },
    /// A router read failed, or the catalog refused a planned request.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// The job could not be recorded or started, for example because another write job
    /// runs on the router.
    #[error(transparent)]
    Job(JobError),
}

/// A step of the setup job, as its structured progress names it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the setup vocabulary the Web, MCP and CLI front ends use"
)]
pub enum SetupStep {
    /// Installing the missing components (a rebooting component commit).
    Components,
    /// Sending `opkg disk <drive> <installer>`.
    Install,
    /// Waiting for the installer's log lines.
    Verify,
    /// Reading `opkg disk` back.
    ReadBack,
    /// Finished.
    Done,
}

impl fmt::Display for SetupStep {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Components => "components",
            Self::Install => "install",
            Self::Verify => "verify",
            Self::ReadBack => "read_back",
            Self::Done => "done",
        })
    }
}

/// The setup job's structured progress.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the setup vocabulary the Web, MCP and CLI front ends use"
)]
pub struct SetupProgress {
    /// The current step.
    pub step: SetupStep,
    /// The last installer step (1 to 5) seen in this attempt's log lines.
    pub installer_step: Option<u8>,
    /// Whether the configuration is unsaved; set when the job finished.
    pub unsaved: Option<bool>,
    /// The final message ([`SAVE_NOTICE`]).
    pub message: Option<&'static str>,
}

impl SetupProgress {
    /// Progress in `step`, with the last installer step seen.
    const fn at(step: SetupStep, installer_step: Option<u8>) -> Self {
        Self {
            step,
            installer_step,
            unsaved: None,
            message: None,
        }
    }
}

/// Why a started setup job failed or ended early: the text of its final record.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the setup vocabulary the Web, MCP and CLI front ends use"
)]
pub enum SetupFailure {
    /// The components were installed, and another writer took the router's lease during
    /// the restart.
    #[error("components installed; run setup again")]
    ComponentsInstalled,
    /// The job was cancelled before `opkg disk` was sent.
    #[error("Entware setup cancelled before the installation was started")]
    CancelledBeforeInstall,
    /// The job was cancelled while the installer runs on the router.
    #[error(
        "cancelled while waiting for the result: the Entware installation continues on the router; check the router log and opkg disk"
    )]
    InstallContinues,
    /// The job was cancelled after the success line and the read-back: the installation
    /// completed and the configuration is unsaved.
    #[error(
        "cancelled after the installation completed: Entware is installed; the configuration is unsaved: save it explicitly"
    )]
    CancelledAfterInstall,
    /// The log read before `opkg disk` returned no record list the job can order by record
    /// id, so this attempt's lines could not be told from older ones; `opkg disk` was not
    /// sent.
    #[error(
        "Entware setup failed in step install: the router log read before the installation returned no usable record list; opkg disk was not sent"
    )]
    BaselineUnusable,
    /// An installer log line of this attempt reported an error.
    #[error(
        "Entware setup failed in step verify: the installer reported an error after installer step {installer_step} of 5"
    )]
    InstallerError {
        /// The last installer step seen before the error (0: none).
        installer_step: u8,
    },
    /// The installer could not run: the archive is for another architecture.
    #[error(
        "Entware setup failed in step verify: the installer cannot run on this router (Exec format error); check the installer choice"
    )]
    WrongArchitecture,
    /// No success line arrived within [`INSTALL_LIMIT`].
    #[error(
        "verification failed: no \"[5/5] \\\"Entware\\\" installed!\" log line within 15 minutes"
    )]
    MarkerMissing,
    /// `opkg disk` does not name the chosen drive after the install.
    #[error("verification failed: opkg disk does not name the chosen drive")]
    ReadBackMismatch,
    /// A request of `step` failed.
    #[error("Entware setup failed in step {step}: {reason}")]
    Step {
        /// The step.
        step: SetupStep,
        /// The failure.
        reason: String,
    },
}

/// What the job needs besides its change set and plan.
struct Setup {
    /// The router registry: restart probes.
    registry: Arc<RouterRegistry>,
    /// The workflow: the fresh change set after a component commit.
    workflow: Arc<ChangeWorkflow>,
    /// The router id.
    router: String,
    /// The audit actor.
    actor: Actor,
    /// The caller's role.
    role: Role,
    /// The router's catalog.
    catalog: Catalog,
}

/// The requests of one admitted setup.
struct Plan {
    /// `components install <name>` for each missing component.
    queue: Vec<CliChangeRequest>,
    /// `components commit`, when a component is missing.
    commit: Option<CliChangeRequest>,
    /// `opkg disk <disk> <installer url>`.
    install: CliChangeRequest,
    /// The disk argument `opkg disk` must read back.
    disk: String,
}

/// Starts the guided Entware setup on router `router_name` as one write job.
///
/// Before the job starts, without changing the router, it checks the role (`Destructive`),
/// the confirmation, that Entware is possible, that the configuration is saved and no
/// fail-safe timer is armed, the installer, the drive, that `opkg disk` is unset and that
/// the router offers the missing components. The job then installs the missing `opkg` and
/// `ext` components (a rebooting component commit, followed by a fresh change set), sends
/// `opkg disk <drive> <installer url>` once, polls the router log every
/// [`POLL_INTERVAL`] for up to [`INSTALL_LIMIT`] for this attempt's installer lines, reads
/// `opkg disk` back and ends with the configuration unsaved. It never saves.
///
/// # Errors
///
/// The refusals of [`SetupError`]; failures after the start are the job's
/// ([`SetupFailure`]).
// NOT cancel-safe: once spawned, the setup job (which may reboot the router) runs on without its id
// reaching the caller.
#[inline]
#[expect(
    clippy::too_many_arguments,
    reason = "the parameters of components::start_commit_job plus the workflow and the actor, as every front end passes them"
)]
pub async fn start(
    jobs: &Arc<JobRunner>,
    registry: Arc<RouterRegistry>,
    workflow: Arc<ChangeWorkflow>,
    router_name: String,
    actor: Actor,
    role: &Role,
    changes: ChangeSet,
    catalog: &Catalog,
    request: SetupRequest,
) -> CoreResult<String, SetupError> {
    authorize(role, Permission::Destructive, &router_name)?;
    if !request.confirmed {
        return Err(SetupError::ConfirmationRequired);
    }
    let router = RouterCtx::new(changes.client(), catalog.clone());
    let plan = preflight::check(&router, &request).await?;
    let setup = Setup {
        registry,
        workflow,
        router: router_name.clone(),
        actor,
        role: role.clone(),
        catalog: catalog.clone(),
    };
    jobs.start(
        "entware.setup".to_owned(),
        JobTarget::Write(router_name),
        async move |context| setup.run(context, changes, plan).await,
    )
    .await
    .map_err(SetupError::Job)
}

/// The `opkg disk <disk> <installer url>` request the setup job sends.
///
/// Destructive, read back from `show rc` `opkg` `disk`. Front ends start the setup with
/// [`start`], which plans this request once its checks passed; this is for inspection.
///
/// # Errors
///
/// [`SetupError::Domain`] when the catalog refuses the request or the line does not render
/// it.
#[inline]
pub fn install_request(
    router: &RouterCtx,
    disk: &str,
    installer: Installer,
) -> CoreResult<CliChangeRequest, SetupError> {
    preflight::install_request(router, disk, installer)
}
