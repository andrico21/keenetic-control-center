//! Protected conversion of preset items into generic migration phases.

use alloc::collections::BTreeSet;

use kcc_config::{config_text::flatten, mask::redact_text};
use secrecy::{ExposeSecret as _, SecretString};

use super::PresetApplyOptions;
use crate::{
    apply::ApplyWarning,
    inventory::TargetInventory,
    planner::{
        ConfigFingerprint, MigrationPlan, PlanItem, PlanPhases, PlannedLine, digest_lines,
        digest_text, is_management_line, plan_id,
    },
    presets::{
        model::Preset,
        plan::{PresetMode, PresetPlan, PresetPlanItem},
    },
};

/// Converts preset reconciliation into the generic migration plan contract.
pub(super) fn migration_plan(
    preset: &Preset,
    plan: PresetPlan,
    target: &TargetInventory,
    options: PresetApplyOptions,
) -> (MigrationPlan, String, Vec<ApplyWarning>) {
    let source = source_text(preset);
    let source_lines = preset
        .lines
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let target_lines = flatten(&target.running_config)
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let mut phases = PlanPhases::default();
    let mut expected = Vec::new();
    let mut warnings = Vec::new();
    let mut items = Vec::with_capacity(plan.items.len());
    for item in plan.items {
        let mut reported = report_item(preset, &item);
        let Some(command) = item.command else {
            items.push(reported);
            if let Some(result) = item.result {
                expected.push(result);
            }
            continue;
        };
        let executable = wireguard_command(command, options, &mut warnings);
        reported.reason_key.clone_from(&executable.1);
        items.push(reported);
        if item.result.is_some() {
            expected.push(executable.0.clone());
        }
        let planned = PlannedLine {
            source_index: item.index,
            display: "<redacted>".to_owned(),
            disposition: item.disposition,
            reason_key: executable.1,
            command: executable.0,
        };
        if is_management_line(
            planned.expose_command(),
            target.management_interface.as_deref(),
            &target.login,
        ) {
            phases.management.push(planned);
        } else if matches!(plan.mode, PresetMode::Mirror)
            && planned.expose_command().starts_with("no ")
        {
            phases.prune.push(planned);
        } else {
            phases.additive.push(planned);
        }
    }
    let source_fingerprint = ConfigFingerprint {
        startup_md5: digest_lines(&source_lines),
        last_change_checksum: digest_text(""),
    };
    let target_fingerprint = ConfigFingerprint {
        startup_md5: target
            .startup_config_md5
            .clone()
            .unwrap_or_else(|| digest_lines(&target_lines)),
        last_change_checksum: target.last_change_checksum.clone(),
    };
    let identity = plan_id(&source_fingerprint, &target_fingerprint, &phases);
    (
        MigrationPlan {
            expected_lines: expected,
            target_running_digest: digest_lines(&target_lines),
            plan_id: identity,
            source_fingerprint,
            target_fingerprint,
            phases,
            reconnect_url: None,
            target_not_clean: false,
            residual: Vec::new(),
            items,
        },
        source,
        warnings,
    )
}

/// The redacted report record of one preset item: its captured line, or for a target-only
/// removal its command, and its resulting line.
fn report_item(preset: &Preset, item: &PresetPlanItem) -> PlanItem {
    let before = preset.lines.get(item.index).map_or_else(
        || item.expose_command().map_or_default(redact_text),
        |line| redact_text(&line.to_string()),
    );
    PlanItem {
        source_index: item.index,
        disposition: item.disposition,
        before,
        after: item.expose_result().map(redact_text),
        reason_key: item.reason.key().to_owned(),
    }
}

/// Replaces a captured WireGuard private key with target-side key generation by default.
fn wireguard_command(
    command: SecretString,
    options: PresetApplyOptions,
    warnings: &mut Vec<ApplyWarning>,
) -> (SecretString, String) {
    let words = command
        .expose_secret()
        .split_whitespace()
        .collect::<Vec<_>>();
    let [interface, name, wireguard, private_key, key @ ..] = words.as_slice() else {
        return (command, "preset-add".to_owned());
    };
    let captured = matches!(key, [_] | ["ns3", _]);
    if *interface != "interface"
        || *wireguard != "wireguard"
        || *private_key != "private-key"
        || !captured
    {
        return (command, "preset-add".to_owned());
    }
    if options.regenerate_wireguard_keys {
        (
            SecretString::from(format!("interface {name} wireguard private-key")),
            "preset-wireguard-regenerate".to_owned(),
        )
    } else {
        warnings.push(ApplyWarning::WireGuardPrivateKeyKept {
            interface: (*name).to_owned(),
        });
        (command, "preset-wireguard-key-kept".to_owned())
    }
}

/// Produces a header-bearing transient source accepted by generic drift checking.
fn source_text(preset: &Preset) -> String {
    let mut output = format!(
        "! $$$ Model: {}\n! $$$ Version: {}\n",
        preset.source.model, preset.source.firmware_version
    );
    for line in &preset.lines {
        output.push_str(&line.to_string());
        output.push('\n');
    }
    output
}
