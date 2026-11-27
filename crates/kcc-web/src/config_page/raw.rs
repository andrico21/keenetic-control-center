//! A raw restore, run as one detached task.
//!
//! The migration applier provides the safety around it: the router's running
//! configuration is planned onto the router itself (an empty plan, so nothing is asked
//! and nothing replayed), and preparing that plan runs the applier's preflight
//! (permission and scope, the write lease, the router's own fresh backup, the drift
//! checks, the recovery timer). The raw restore then uploads the backup as the router's
//! saved configuration, restarts the router, and checks the result against the file by
//! the router's own checksum, refusing another model or newer firmware first.

use alloc::sync::Arc;

use kcc_app::{
    audit::{Actor, ActorKind, AuditLog},
    permissions::Role,
    registry::RouterRegistry,
    workflow::ChangeWorkflow,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_migrate::{
    apply::{Applier, ApplyError, ApplyRequest, ApplySource, RawRestore},
    inventory::{InventoryClient, InventoryError, TargetInventory},
    planner::{Choices, MigrationMaps, PlanError, Planner},
    source::SourceConfig,
};
use kcc_rci::{ConfigKind, SecretBytes};
use secrecy::ExposeSecret as _;

use super::store::Opened;
use crate::page_kit::{
    family::Family,
    outcome::Failure,
    read_failure::{ReadProblem, rci_problem, registry_problem},
};

/// Everything one raw restore needs, owned by its task.
pub(crate) struct RawJob {
    /// The change workflow the applier leases the router through.
    workflow: Arc<ChangeWorkflow>,
    /// Router profiles and clients.
    registry: Arc<RouterRegistry>,
    /// Audit writer for the applier's own records.
    audit: AuditLog,
    /// Who restores.
    actor: Actor,
    /// Their role and scope.
    role: Role,
    /// Router profile id.
    router: String,
    /// The backup's text.
    bytes: SecretBytes,
    /// Language of the applier's progress messages.
    locale: Locale,
}

impl RawJob {
    /// The raw restore of a backup with text `bytes`, for the action `opened`; `None`
    /// without fleet services.
    pub(crate) fn new(opened: &Opened<'_>, bytes: SecretBytes) -> Option<Self> {
        let (state, user) = (opened.state(), opened.user());
        let fleet = state.fleet()?;
        Some(Self {
            workflow: Arc::clone(fleet.workflow()),
            registry: Arc::clone(fleet.registry()),
            audit: state.audit().clone(),
            actor: Actor::new(ActorKind::Web, user.username().to_owned()),
            role: user.role().clone(),
            router: opened.router().to_owned(),
            bytes,
            locale: user.locale(),
        })
    }
}

/// Why a raw restore stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RawFailure {
    /// The backup is not a configuration.
    Unreadable,
    /// The router could not be read to plan the restore, for this reason.
    Router(ReadProblem),
    /// The plan needs choices only the migration wizard asks for.
    NeedsWizard,
    /// The applier refused or failed.
    Apply(ApplyError),
}

impl RawFailure {
    /// The failure a page shows, in `locale`, with its audit outcome.
    pub(crate) fn failure(&self, locale: Locale) -> Failure {
        let (key, audit) = match self {
            Self::Router(problem) => return problem.failure(locale, "unreachable"),
            Self::Unreadable => (keys::WEB_CONFIG_RAW_UNREADABLE, "unreadable"),
            Self::NeedsWizard => (keys::WEB_CONFIG_RAW_WIZARD, "needs_wizard"),
            Self::Apply(ApplyError::HardwareMismatch) => {
                (keys::WEB_CONFIG_RAW_HARDWARE, "hardware_mismatch")
            }
            Self::Apply(ApplyError::Firmware) => (keys::WEB_CONFIG_RAW_FIRMWARE, "firmware"),
            Self::Apply(ApplyError::UnverifiedFirmwareTier) => {
                (keys::WEB_CONFIG_RAW_WIZARD, "unverified_firmware")
            }
            Self::Apply(ApplyError::AgreementRequired) => {
                (keys::WEB_CONFIG_RAW_WIZARD, "agreement_required")
            }
            Self::Apply(ApplyError::Verification) => {
                (keys::WEB_CONFIG_RAW_UNVERIFIED, "verification_failed")
            }
            Self::Apply(ApplyError::Unreachable | ApplyError::RolledBackByRouter) => {
                (keys::WEB_CONFIG_RAW_LOST, "unreachable")
            }
            Self::Apply(_) => (keys::WEB_CONFIG_RAW_FAILED, "failed"),
        };
        Failure::new(tr(locale, key, None), audit)
    }
}

/// Why reading the router's inventory failed with `error`, as the page says it.
fn inventory_problem(error: &InventoryError) -> ReadProblem {
    match error {
        InventoryError::Rci(rci) => rci_problem(Family::Changes, rci),
        InventoryError::ConfigEncoding | InventoryError::Parse(_) => {
            ReadProblem::from(keys::WEB_KIT_UNREADABLE)
        }
        InventoryError::SourceVersionRequired
        | InventoryError::UnsupportedFirmware
        | InventoryError::TargetFirmwareOlder {
            source_version: _,
            target_version: _,
        }
        | InventoryError::Catalog
        | _ => ReadProblem::from(Family::Changes.failed()),
    }
}

/// Prepares the applier on the router and runs the raw restore of `job`.
///
/// # Errors
///
/// Returns why the restore stopped.
// NOT cancel-safe: the upload replaces the router's saved configuration before the
// restart; callers run it as its own task.
pub(crate) async fn run(job: RawJob) -> Result<(), RawFailure> {
    let client = job.registry.client(&job.router).await.map_err(|error| {
        tracing::warn!(%error, router = job.router, "raw restore: no router client");
        RawFailure::Router(registry_problem(Family::Changes, &error))
    })?;
    let running = client
        .download_config(ConfigKind::Running)
        .await
        .map_err(|error| RawFailure::Router(rci_problem(Family::Changes, &error)))?;
    let current = SourceConfig::from_bytes(running.expose_secret())
        .map_err(|_error| RawFailure::Router(ReadProblem::from(keys::WEB_KIT_UNREADABLE)))?;
    let inventory =
        TargetInventory::collect(&InventoryClient::from_client(&client), current.firmware)
            .await
            .map_err(|error| {
                tracing::warn!(%error, router = job.router, "raw restore: inventory failed");
                RawFailure::Router(inventory_problem(&error))
            })?;
    let plan = Planner::plan(
        &current,
        &inventory,
        &MigrationMaps::default(),
        &Choices::default(),
    )
    .map_err(|error| match error {
        PlanError::PlanBlocked { items: _ } => RawFailure::NeedsWizard,
        PlanError::Rules(_) | _ => RawFailure::Apply(ApplyError::Validation),
    })?;
    let mut request = ApplyRequest::new(
        job.workflow,
        job.audit,
        job.actor,
        job.role,
        job.router,
        plan,
        ApplySource::File(running),
    );
    request.options.locale = job.locale;
    let applier = Applier::prepare(request).await.map_err(RawFailure::Apply)?;
    let mut restore = RawRestore::new(applier, true).map_err(RawFailure::Apply)?;
    restore.restore(&job.bytes).await.map_err(RawFailure::Apply)
}
