//! Ordered, idempotent migration planning.

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Write as _;

use kcc_config::{
    config_text::{Token, flatten},
    secrets::redact,
};
use md5::{Digest as _, Md5};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    inventory::TargetInventory,
    maps::{InterfaceMap, PortMap, RadioMap},
    rules::{
        ClassificationChoices, ClassificationTarget, ClassifiedItem, Disposition, RuleEngine,
        RuleError,
    },
    source::SourceConfig,
};

/// The three editable mapping domains consumed by the planner.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct MigrationMaps {
    /// Physical-port mappings.
    pub ports: PortMap,
    /// Wi-Fi-radio mappings.
    pub radios: RadioMap,
    /// Logical-interface mappings.
    pub interfaces: InterfaceMap,
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
}

impl Choices {
    /// Sets the operator-confirmed management reconnect URL.
    #[inline]
    #[must_use]
    pub fn with_reconnect_url(mut self, reconnect_url: String) -> Self {
        self.reconnect_url = Some(reconnect_url);
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct PlannedLine {
    /// Original source-order index; prune entries sort after additive entries.
    pub source_index: usize,
    /// Executable CLI command. This field belongs to the plan, never to a report.
    pub command: String,
    /// Redacted command suitable for display.
    pub display: String,
    /// Classification disposition.
    pub disposition: Disposition,
    /// Localization key explaining this item.
    pub reason_key: String,
}

/// Ordered execution phases.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
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

/// Complete migration plan consumed by dry-run reporting and the later applier.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub struct MigrationPlan {
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
    /// Normalized target lines absent from source and not selected for pruning.
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

/// Stateless migration planner.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct Planner;

impl Planner {
    /// Produces an ordered, idempotent plan without contacting either router.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError::PlanBlocked`] while classification or management reconnect input is
    /// unresolved, and [`PlanError::Rules`] when embedded policy cannot be loaded.
    #[inline]
    #[expect(
        clippy::too_many_lines,
        reason = "the planner keeps classification, diffing, and phase partitioning in replay order"
    )]
    pub fn plan(
        source: &SourceConfig,
        target: &TargetInventory,
        maps: &MigrationMaps,
        choices: &Choices,
    ) -> Result<MigrationPlan, PlanError> {
        let classification_choices = ClassificationChoices::new(
            &maps.ports,
            &maps.radios,
            &maps.interfaces,
            &choices.new_passwords,
            &choices.overwrite_scalars,
        );
        let classification_target = ClassificationTarget::new(
            Some(&target.catalog),
            &target.running_config,
            &target.installed_components,
            target.realm.as_deref(),
        );
        let classified = RuleEngine::embedded()?.classify(
            &source.ast,
            classification_target,
            &classification_choices,
        )?;
        let blocked = classified
            .iter()
            .filter(|item| {
                matches!(
                    item.disposition,
                    Disposition::NeedsInput | Disposition::Conflict
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        if !blocked.is_empty() {
            return Err(PlanError::PlanBlocked { items: blocked });
        }

        let target_lines = flatten(&target.running_config);
        let target_normalized = target_lines
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let source_normalized = flatten(&source.ast)
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let target_redacted = target_lines
            .iter()
            .zip(flatten(&redact(&target.running_config)))
            .map(|(original, mut line)| {
                redact_ns3_tokens(&mut line.tokens);
                (original.to_string(), line.to_string())
            })
            .collect::<BTreeMap<_, _>>();
        let residual = target_normalized
            .difference(&source_normalized)
            .filter(|line| !choices.prune_lines.contains(*line))
            .map(|line| {
                target_redacted
                    .get(line)
                    .cloned()
                    .unwrap_or_else(|| line.clone())
            })
            .collect::<Vec<_>>();
        let mut phases = PlanPhases::default();
        for item in &classified {
            if !matches!(item.disposition, Disposition::Copy | Disposition::Remap) {
                continue;
            }
            let Some(output) = item.output.as_ref() else {
                continue;
            };
            let command = output.expose_secret();
            if target_normalized.contains(command) {
                continue;
            }
            let planned = PlannedLine {
                source_index: item.source_index,
                command: command.to_owned(),
                display: item.after.clone().unwrap_or_else(|| item.before.clone()),
                disposition: item.disposition,
                reason_key: item.reason_key.clone(),
            };
            if is_management_line(command, target.management_interface.as_deref()) {
                phases.management.push(planned);
            } else {
                phases.additive.push(planned);
            }
        }
        for (offset, line) in choices.prune_lines.iter().enumerate() {
            if target_normalized.contains(line) && !source_normalized.contains(line) {
                phases.prune.push(PlannedLine {
                    source_index: classified.len().saturating_add(offset),
                    command: format!("no {line}"),
                    display: format!(
                        "no {}",
                        target_redacted
                            .get(line)
                            .map_or(line.as_str(), String::as_str)
                    ),
                    disposition: Disposition::Remap,
                    reason_key: "migration-reason-operator-prune".to_owned(),
                });
            }
        }
        let reconnect_url = (!phases.management.is_empty())
            .then(|| choices.reconnect_url.clone())
            .flatten();
        if !phases.management.is_empty() && reconnect_url.is_none() {
            let management = phases
                .management
                .first()
                .map_or_else(synthetic_management_item, synthetic_blocked_item);
            return Err(PlanError::PlanBlocked {
                items: vec![management],
            });
        }
        let source_fingerprint = ConfigFingerprint {
            startup_md5: source
                .header
                .md5
                .clone()
                .unwrap_or_else(|| digest_lines(&source_normalized)),
            last_change_checksum: digest_text(
                source.header.last_change.as_deref().unwrap_or_default(),
            ),
        };
        let target_fingerprint = ConfigFingerprint {
            startup_md5: target
                .startup_config_md5
                .clone()
                .unwrap_or_else(|| digest_lines(&target_normalized)),
            last_change_checksum: target.last_change_checksum.clone(),
        };
        let items = classified
            .iter()
            .map(|item| PlanItem {
                source_index: item.source_index,
                disposition: item.disposition,
                before: item.before.clone(),
                after: item.after.clone(),
                reason_key: item.reason_key.clone(),
            })
            .collect::<Vec<_>>();
        let plan_id = plan_id(&source_fingerprint, &target_fingerprint, &phases);
        Ok(MigrationPlan {
            plan_id,
            source_fingerprint,
            target_fingerprint,
            phases,
            reconnect_url,
            target_not_clean: !residual.is_empty(),
            residual,
            items,
        })
    }
}

/// Identifies commands that can cut off the current management connection.
fn is_management_line(line: &str, management_interface: Option<&str>) -> bool {
    let words = line.split_whitespace().collect::<Vec<_>>();
    match words.as_slice() {
        ["ip", "http", "port" | "ssl", ..] => true,
        ["interface", interface, rest @ ..] => management_interface.is_some_and(|current| {
            current == *interface && matches!(rest, ["ip", "address" | "security-level", ..])
        }),
        _ => false,
    }
}

/// Redacts typed NS3 payloads regardless of command shape.
fn redact_ns3_tokens(tokens: &mut [Token]) {
    for token in tokens {
        if let Token::Ns3(payload) = token {
            "<redacted>".clone_into(payload);
        }
    }
}

/// Creates the operator-input record for an unconfirmed reconnect URL.
fn synthetic_blocked_item(line: &PlannedLine) -> ClassifiedItem {
    ClassifiedItem {
        source_index: line.source_index,
        line_no: 0,
        disposition: Disposition::NeedsInput,
        rule_id: "management-reconnect".to_owned(),
        reason_key: "migration-reason-management-reconnect".to_owned(),
        before: line.display.clone(),
        after: Some(line.display.clone()),
        needed_input: Some("confirm reconnect URL".to_owned()),
        output: None,
    }
}

/// Defensive fallback for an impossible empty management phase.
fn synthetic_management_item() -> ClassifiedItem {
    ClassifiedItem {
        source_index: 0,
        line_no: 0,
        disposition: Disposition::NeedsInput,
        rule_id: "management-reconnect".to_owned(),
        reason_key: "migration-reason-management-reconnect".to_owned(),
        before: String::new(),
        after: None,
        needed_input: Some("confirm reconnect URL".to_owned()),
        output: None,
    }
}

/// Computes a lowercase MD5 string.
fn digest_text(text: &str) -> String {
    let mut digest = String::with_capacity(32);
    for byte in Md5::digest(text.as_bytes()) {
        let _result = write!(digest, "{byte:02x}");
    }
    digest
}

/// Hashes a normalized set with unambiguous line separators.
fn digest_lines(lines: &BTreeSet<String>) -> String {
    digest_text(&lines.iter().cloned().collect::<Vec<_>>().join("\n"))
}

/// Derives the plan identity from drift identities and executable phase content.
fn plan_id(source: &ConfigFingerprint, target: &ConfigFingerprint, phases: &PlanPhases) -> String {
    let commands = phases
        .additive
        .iter()
        .chain(&phases.prune)
        .chain(&phases.management)
        .map(|line| line.command.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    digest_text(&format!(
        "{}\n{}\n{}\n{}\n{commands}",
        source.startup_md5,
        source.last_change_checksum,
        target.startup_md5,
        target.last_change_checksum
    ))
}
