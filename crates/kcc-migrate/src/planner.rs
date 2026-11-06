//! Ordered, idempotent migration planning.

#![expect(
    clippy::pub_use,
    reason = "preserve the public planner facade after type extraction"
)]

mod diff;
mod types;

use alloc::collections::BTreeSet;

use diff::{digest_lines, digest_text, is_management_line, plan_id};
use kcc_config::config_text::flatten;
use secrecy::SecretString;

pub use self::types::{
    Choices, ConfigFingerprint, MigrationMaps, MigrationPlan, PlanError, PlanItem, PlanPhases,
    PlannedLine,
};
use crate::{
    inventory::TargetInventory,
    rules::{ClassificationChoices, ClassificationTarget, ClassifiedItem, Disposition, RuleEngine},
    source::SourceConfig,
};

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
        let target_normalized = flatten(&target.running_config)
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let source_normalized = flatten(&source.ast)
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let mut phases = execution_phases(&classified, &target_normalized, target);
        for (offset, line) in choices.prune_lines.iter().enumerate() {
            if target_normalized.contains(line) && !source_normalized.contains(line) {
                phases.prune.push(PlannedLine {
                    non_critical: false,
                    source_index: classified.len().saturating_add(offset),
                    command: SecretString::from(format!("no {line}")),
                    display: "<redacted>".to_owned(),
                    disposition: Disposition::Remap,
                    reason_key: "migration-reason-operator-prune".to_owned(),
                });
            }
        }
        let reconnect_url = (!phases.management.is_empty())
            .then(|| choices.reconnect_url.clone())
            .flatten();
        if let Some(management) = phases.management.first()
            && reconnect_url.is_none()
        {
            return Err(PlanError::PlanBlocked {
                items: vec![blocked_management(management)],
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
        let residual = target_normalized
            .difference(&source_normalized)
            .filter(|line| !choices.prune_lines.contains(*line))
            .map(|_line| "<redacted>".to_owned())
            .collect::<Vec<_>>();
        Ok(MigrationPlan {
            expected_lines: classified
                .iter()
                .filter_map(|item| item.output.clone())
                .collect(),
            target_running_digest: digest_lines(&target_normalized),
            plan_id: plan_id(&source_fingerprint, &target_fingerprint, &phases),
            source_fingerprint,
            target_fingerprint,
            phases,
            reconnect_url,
            target_not_clean: !residual.is_empty(),
            residual,
            items: classified.iter().map(PlanItem::from).collect(),
        })
    }
}

/// Partitions executable outputs without copying secret text into ordinary strings.
fn execution_phases(
    classified: &[ClassifiedItem],
    target_normalized: &BTreeSet<String>,
    target: &TargetInventory,
) -> PlanPhases {
    let mut phases = PlanPhases::default();
    for item in classified {
        if !matches!(item.disposition, Disposition::Copy | Disposition::Remap) {
            continue;
        }
        let Some(output) = item.output.as_ref() else {
            continue;
        };
        let planned = PlannedLine {
            non_critical: item.reason_key == "migration-reason-non-critical-description",
            source_index: item.source_index,
            command: output.clone(),
            display: "<redacted>".to_owned(),
            disposition: item.disposition,
            reason_key: item.reason_key.clone(),
        };
        if target_normalized.contains(planned.expose_command()) {
            continue;
        }
        if is_management_line(
            planned.expose_command(),
            target.management_interface.as_deref(),
        ) {
            phases.management.push(planned);
        } else {
            phases.additive.push(planned);
        }
    }
    phases
}

/// Creates an input requirement for an unconfirmed reconnect URL.
fn blocked_management(line: &PlannedLine) -> ClassifiedItem {
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
