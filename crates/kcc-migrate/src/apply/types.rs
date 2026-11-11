//! Applier inputs and value-free outcomes.

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt::Debug, pin::Pin, time::Duration};

use kcc_app::{
    audit::{Actor, AuditLog},
    backups::BackupStore,
    permissions::Role,
    workflow::ChangeWorkflow,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::{RciClient, SecretBytes, version::FirmwareVersion};
use secrecy::SecretString;
use serde::Serialize;
use thiserror::Error;
use tokio::time::{Instant, sleep};

use crate::planner::MigrationPlan;

/// Monotonic time and asynchronous waiting, injectable for deterministic router recovery.
pub trait Clock: Debug + Send + Sync {
    /// Returns elapsed time on this clock.
    fn now(&self) -> Duration;
    /// Advances or waits until the supplied duration has elapsed.
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Tokio-backed production recovery clock.
#[derive(Debug)]
#[non_exhaustive]
pub struct SystemClock {
    /// Clock origin.
    origin: Instant,
}

impl Default for SystemClock {
    #[inline]
    fn default() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    #[inline]
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
    #[inline]
    fn wait(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(sleep(duration))
    }
}

/// Selected source; file and backup variants never open a source router connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum ApplySource {
    /// Registered, permission-scoped source router.
    LiveRouter {
        /// Source profile id.
        id: String,
        /// Policy-checked client.
        client: Arc<RciClient>,
    },
    /// Uploaded startup configuration.
    File(SecretBytes),
    /// Encrypted stored backup.
    Backup {
        /// Backup store.
        store: Arc<BackupStore>,
        /// Owning router id.
        router: String,
        /// Backup name.
        name: String,
    },
    /// In-memory preset source; never persisted outside the encrypted preset store.
    Preset {
        /// Header-bearing source configuration retained in protected bytes.
        bytes: SecretBytes,
        /// Registered source router whose scope must be authorized, when any.
        source_router: Option<String>,
    },
}

/// Error handling for explicitly non-critical commands.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum StopPolicy {
    /// Never submit another line after an error.
    #[default]
    StopOnError,
    /// Retry non-critical description lines once after the additive pass.
    ContinueOnNonCritical,
}

/// Operator choices shared by preflight, execution, and finishing.
#[derive(Debug)]
#[non_exhaustive]
pub struct ApplyOptions {
    /// Explicitly approved component installations; completion requires a fresh reviewed plan.
    pub install_components: Vec<String>,
    /// Uses plaintext secret transport when the target is known to reject NS3 input.
    pub decode_ns3: bool,
    /// Explicit acknowledgement for documentation-based firmware.
    pub ack_documentation_tier: bool,
    /// Exact router document text confirmed by the operator, keyed by dpn/eula.
    pub agreements: BTreeMap<String, String>,
    /// Initial admin password for factory setup.
    pub admin_password: Option<SecretString>,
    /// Primary password after a reviewed management password command.
    pub management_password: Option<SecretString>,
    /// Explicit firmware when the uploaded source has no usable version header.
    pub source_firmware: Option<FirmwareVersion>,
    /// Router recovery interval, 300 through 3600 seconds.
    pub safety_seconds: u64,
    /// Stop policy.
    pub stop_policy: StopPolicy,
    /// Time source.
    pub clock: Arc<dyn Clock>,
    /// Progress message language.
    pub locale: Locale,
    /// Warnings established while converting a reviewed specialized plan.
    pub initial_warnings: Vec<ApplyWarning>,
}

impl Default for ApplyOptions {
    #[inline]
    fn default() -> Self {
        Self {
            install_components: Vec::new(),
            decode_ns3: false,
            ack_documentation_tier: false,
            agreements: BTreeMap::new(),
            admin_password: None,
            management_password: None,
            source_firmware: None,
            safety_seconds: 900,
            stop_policy: StopPolicy::StopOnError,
            clock: Arc::new(SystemClock::default()),
            locale: Locale::En,
            initial_warnings: Vec::new(),
        }
    }
}

/// Complete reviewed input for one migration job.
#[derive(Debug)]
#[non_exhaustive]
pub struct ApplyRequest {
    /// Workflow services.
    pub workflow: Arc<ChangeWorkflow>,
    /// Actor audit writer.
    pub audit: AuditLog,
    /// Initiating actor.
    pub actor: Actor,
    /// Actor permissions and scope.
    pub role: Role,
    /// Registered target id.
    pub target: String,
    /// Reviewed plan.
    pub plan: MigrationPlan,
    /// Original source.
    pub source: ApplySource,
    /// Operator choices.
    pub options: ApplyOptions,
}

impl ApplyRequest {
    /// Creates a request with conservative defaults; operator acknowledgements remain unset.
    #[inline]
    #[must_use]
    pub fn new(
        workflow: Arc<ChangeWorkflow>,
        audit: AuditLog,
        actor: Actor,
        role: Role,
        target: String,
        plan: MigrationPlan,
        source: ApplySource,
    ) -> Self {
        Self {
            workflow,
            audit,
            actor,
            role,
            target,
            plan,
            source,
            options: ApplyOptions::default(),
        }
    }
}

/// Public progress without command text or router-controlled messages.
#[derive(Clone, Debug, Default, Serialize)]
#[non_exhaustive]
pub struct ApplyReport {
    /// Redacted normalized target-only lines, retaining one entry per residual setting.
    pub residual: Vec<String>,
    /// Successfully applied source indices.
    pub applied: Vec<usize>,
    /// Rejected source indices.
    pub failed: Vec<usize>,
    /// Number of normalized target-only lines left after apply.
    pub residual_count: usize,
    /// Whether read-back and health checks passed.
    pub verified: bool,
    /// Whether an explicit finish operation completed.
    pub finished: bool,
    /// Typed final failure when apply stopped.
    pub failure: Option<ApplyError>,
    /// Non-secret WireGuard public identities produced by router-side key generation.
    pub wireguard_public_keys: Vec<WireGuardPublicKey>,
    /// Stable warnings requiring operator attention.
    pub warnings: Vec<ApplyWarning>,
}

/// A generated WireGuard public identity safe for reports.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct WireGuardPublicKey {
    /// Interface whose private key was generated by the target router.
    pub interface: String,
    /// Public key reported by the target router.
    pub public_key: String,
}

/// Stable apply warnings localized by presentation layers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ApplyWarning {
    /// A captured WireGuard private key was deliberately reused.
    WireGuardPrivateKeyKept {
        /// Interface retaining the captured key.
        interface: String,
    },
}

impl ApplyReport {
    /// Renders the execution outcome using the selected Fluent locale.
    #[inline]
    #[must_use]
    pub fn message(&self, locale: Locale) -> String {
        let key = match self.failure {
            Some(ApplyError::SavedDisarmFailed) => keys::FINISH_SAVED_ARMED,
            Some(ApplyError::DisarmFailed) => keys::MANAGEMENT_DISARM_FAILED,
            Some(ApplyError::FinishFailed) => keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
            Some(ApplyError::UnverifiedFirmwareTier) => keys::MIGRATE_APPLY_TIER,
            Some(ApplyError::AgreementRequired) => keys::MIGRATE_APPLY_AGREEMENT,
            Some(ApplyError::RolledBackByRouter) => keys::MIGRATE_APPLY_ROUTER_ROLLBACK,
            Some(ApplyError::Verification) if self.finished => keys::MIGRATE_APPLY_RESTORED,
            Some(_) => keys::MIGRATE_APPLY_FAILED,
            None if self.finished => keys::MIGRATE_DONE,
            None if self.verified => keys::MIGRATE_APPLY_VERIFIED,
            None => keys::MIGRATE_START,
        };
        tr(locale, key, None)
    }
}

/// Value-free migration failures; front ends localize these stable categories.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ApplyError {
    /// Components changed the inventory; the caller must collect and review a fresh plan.
    #[error("migration inventory changed; review a new plan")]
    ReplanRequired,
    /// Firmware acknowledgement is absent.
    #[error("unverified firmware tier")]
    UnverifiedFirmwareTier,
    /// Reviewed fingerprints no longer match.
    #[error("migration plan drift")]
    Drift,
    /// Source and target have the same origin.
    #[error("source and target origins collide")]
    SameRouter,
    /// Authentication or source acquisition failed.
    #[error("migration source unavailable")]
    Source,
    /// Target firmware is too old or unknown.
    #[error("incompatible target firmware")]
    Firmware,
    /// Agreements require confirmation of their current text.
    #[error("router agreement confirmation required")]
    AgreementRequired,
    /// Required operator password is missing.
    #[error("router password required")]
    PasswordRequired,
    /// An option or command failed boundary validation.
    #[error("invalid migration input")]
    Validation,
    /// Protected workflow refused the operation.
    #[error("migration workflow failed")]
    Workflow,
    /// Verified work remains applied but its recovery timer could not be disarmed.
    #[error("migration recovery timer remains armed")]
    DisarmFailed,
    /// Configuration was saved, but recovery disarm could not be confirmed.
    #[error("migration configuration saved; recovery timer remains armed")]
    SavedDisarmFailed,
    /// Closing could not be confirmed, so recovery must still be treated as armed.
    #[error("migration closing outcome unknown; recovery timer remains armed")]
    FinishFailed,
    /// A router line failed under the selected stop policy.
    #[error("migration stopped on command error")]
    Stopped,
    /// Read-back or health checks failed.
    #[error("migration verification failed")]
    Verification,
    /// Router recovery restored the original startup state after timer expiry.
    #[error("migration rolled back by router")]
    RolledBackByRouter,
    /// Router did not return within the recovery bound.
    #[error("migration target unreachable")]
    Unreachable,
    /// The caller cancelled the job.
    #[error("migration cancelled")]
    Cancelled,
    /// Job admission failed.
    #[error("migration job unavailable")]
    Job,
    /// Hardware identity differs for raw restore.
    #[error("raw restore hardware mismatch")]
    HardwareMismatch,
}

impl ApplyError {
    /// Whether a failed finish leaves recovery armed or its disarm unconfirmed.
    #[inline]
    #[must_use]
    pub const fn recovery_armed(self) -> bool {
        matches!(
            self,
            Self::FinishFailed | Self::DisarmFailed | Self::SavedDisarmFailed
        )
    }
}
