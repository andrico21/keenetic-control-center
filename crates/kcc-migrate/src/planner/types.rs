//! Executable plan types with one-way, redacted serialization.

use alloc::collections::{BTreeMap, BTreeSet};

use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::{
    maps::{InterfaceMap, PortMap, RadioMap},
    rules::{ClassifiedItem, Disposition, RuleError},
};

/// Editable mapping domains consumed by migration and preset planners.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct MigrationMaps {
    /// Physical-port mappings.
    pub ports: PortMap,
    /// Wi-Fi-radio mappings.
    pub radios: RadioMap,
    /// Logical-interface mappings.
    pub interfaces: InterfaceMap,
    /// Named policy mappings used by DNS routes and policy references.
    pub policies: BTreeMap<String, String>,
}

/// Operator decisions that are not object mappings.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Choices {
    /// Replacement passwords keyed by user name.
    pub new_passwords: BTreeMap<String, SecretString>,
    /// Scalar identities approved for overwrite.
    pub overwrite_scalars: BTreeSet<String>,
    /// Exact normalized target lines selected for pruning.
    pub prune_lines: BTreeSet<String>,
    /// Operator-confirmed URL expected after management changes.
    pub reconnect_url: Option<String>,
    /// Explicit acknowledgement for documentation-only target firmware.
    pub ack_documentation_tier: bool,
}

impl Choices {
    /// Sets the operator-confirmed management reconnect URL.
    #[inline]
    #[must_use]
    pub fn with_reconnect_url(mut self, reconnect_url: String) -> Self {
        self.reconnect_url = Some(reconnect_url);
        self
    }

    /// Acknowledges a documentation-only target firmware tier.
    #[inline]
    #[must_use]
    pub const fn with_documentation_tier_acknowledgement(mut self) -> Self {
        self.ack_documentation_tier = true;
        self
    }
}

/// Drift identity captured while the plan is produced.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct ConfigFingerprint {
    /// Startup-configuration MD5, supplied by the router or computed canonically.
    pub startup_md5: String,
    /// Checksum of the observed `show last-change` identity.
    pub last_change_checksum: String,
}

/// One executable line and its redacted reporting facts.
///
/// Serialization is a printable projection, never executable persistence.
/// Deserialization is deliberately unavailable: a redacted command cannot be replayed.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct PlannedLine {
    /// Whether the migration rule permits a deferred retry after rejection.
    pub non_critical: bool,
    /// Original source-order index; prune entries sort after additive entries.
    pub source_index: usize,
    /// Zeroizing executable command; serialization always replaces its entire text.
    #[serde(serialize_with = "serialize_command")]
    pub command: SecretString,
    /// Redacted command suitable for display.
    pub display: String,
    /// Classification disposition.
    pub disposition: Disposition,
    /// Localization key explaining this item.
    pub reason_key: String,
}

impl PlannedLine {
    /// Borrows executable text for protected transport only; never use in diagnostics.
    #[inline]
    #[must_use]
    pub fn expose_command(&self) -> &str {
        self.command.expose_secret()
    }
}

/// Serializes only the redaction marker, without exposing or copying executable bytes.
///
/// # Errors
///
/// Returns the serializer's output error.
fn serialize_command<S>(_command: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str("<redacted>")
}

/// Ordered execution phases; its serialized form contains no executable commands.
#[derive(Clone, Debug, Default, Serialize)]
#[non_exhaustive]
pub struct PlanPhases {
    /// Non-management additions in source replay order.
    pub additive: Vec<PlannedLine>,
    /// Operator-selected removals, after every addition.
    pub prune: Vec<PlannedLine>,
    /// Connectivity-affecting commands, always last.
    pub management: Vec<PlannedLine>,
}

/// One redacted classification record retained for reports.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct PlanItem {
    /// Source replay index.
    pub source_index: usize,
    /// Selected disposition.
    pub disposition: Disposition,
    /// Redacted original command.
    pub before: String,
    /// Redacted resulting command.
    pub after: Option<String>,
    /// Localization key explaining the decision.
    pub reason_key: String,
}

impl From<&ClassifiedItem> for PlanItem {
    #[inline]
    fn from(item: &ClassifiedItem) -> Self {
        Self {
            source_index: item.source_index,
            disposition: item.disposition,
            before: "<redacted>".to_owned(),
            after: item.after.as_ref().map(|_line| "<redacted>".to_owned()),
            reason_key: item.reason_key.clone(),
        }
    }
}

/// In-memory executable migration plan with a one-way redacted JSON projection.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct MigrationPlan {
    /// Every selected resulting source line, including lines already present on the target.
    #[serde(skip)]
    pub expected_lines: Vec<SecretString>,
    /// Canonical running configuration digest captured for apply-time drift detection.
    pub target_running_digest: String,
    /// Content-derived stable plan identity.
    pub plan_id: String,
    /// Source identity used for drift detection.
    pub source_fingerprint: ConfigFingerprint,
    /// Target identity used for drift detection.
    pub target_fingerprint: ConfigFingerprint,
    /// Ordered execution phases.
    pub phases: PlanPhases,
    /// URL confirmed by the operator for reconnecting after the management phase.
    pub reconnect_url: Option<String>,
    /// Warns that non-default target settings remain before apply.
    pub target_not_clean: bool,
    /// Redacted target lines absent from source and not selected for pruning.
    pub residual: Vec<String>,
    /// Every classified source item, redacted for report generation.
    pub items: Vec<PlanItem>,
}

/// Planning failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PlanError {
    /// One or more classified items still need operator input.
    #[error("migration plan is blocked by unresolved items")]
    PlanBlocked {
        /// Blocking items in source order.
        items: Vec<ClassifiedItem>,
    },
    /// Embedded classification policy is invalid.
    #[error("migration classification failed")]
    Rules(#[from] RuleError),
}
