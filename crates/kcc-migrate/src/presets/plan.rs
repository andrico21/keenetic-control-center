//! Pure preset planning against an already collected target inventory.

mod classify;

use alloc::collections::BTreeSet;
use core::{fmt, str::FromStr as _};

use kcc_config::config_text::flatten;
use kcc_rci::{capabilities::SupportTier, version::FirmwareVersion};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use thiserror::Error;

use super::model::Preset;
use crate::{
    apply,
    inventory::TargetInventory,
    planner::{Choices, MigrationMaps},
    rules::Disposition,
};

/// How target settings in selected groups are reconciled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum PresetMode {
    /// Add or update preset lines without removing target-only lines.
    Merge,
    /// Merge, then remove target-only lines owned by the preset's selected groups.
    Mirror,
}

/// Operator input that still blocks one preset item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum PresetInput {
    /// A source object has no target mapping.
    Mapping {
        /// Unmapped source object name.
        source: String,
    },
    /// A realm-bound router-user hash needs a replacement password.
    RouterUserPassword {
        /// Router user requiring a replacement password.
        user: String,
    },
}

/// One source or target line classified for preset application.
#[derive(Clone, Serialize)]
#[non_exhaustive]
pub struct PresetPlanItem {
    /// Stable plan-order index.
    pub index: usize,
    /// Resulting treatment.
    pub disposition: Disposition,
    /// Protected executable command when this item can run.
    #[serde(skip)]
    pub command: Option<SecretString>,
    /// Protected resulting line, including lines already present on the target.
    #[serde(skip)]
    pub result: Option<SecretString>,
    /// Operator input required before execution.
    pub needed_input: Option<PresetInput>,
    /// Stable machine-readable reason.
    pub reason: String,
}

impl fmt::Debug for PresetPlanItem {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            index,
            disposition,
            command: _,
            result: _,
            needed_input,
            reason,
        } = self;
        f.debug_struct("PresetPlanItem")
            .field("index", index)
            .field("disposition", disposition)
            .field("command", &"<redacted>")
            .field("needed_input", needed_input)
            .field("reason", reason)
            .finish()
    }
}

impl PresetPlanItem {
    /// Borrows executable command text for protected transport.
    #[inline]
    #[must_use]
    pub fn expose_command(&self) -> Option<&str> {
        self.command.as_ref().map(SecretString::expose_secret)
    }

    /// Borrows the resulting configured line for protected verification.
    #[inline]
    #[must_use]
    pub fn expose_result(&self) -> Option<&str> {
        self.result.as_ref().map(SecretString::expose_secret)
    }
}

/// Reviewed preset reconciliation plan.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public aggregate is explicitly named PresetPlan"
)]
pub struct PresetPlan {
    /// Requested reconciliation mode.
    pub mode: PresetMode,
    /// Source and mirror-removal items in execution order.
    pub items: Vec<PresetPlanItem>,
    /// Whether applying to a documentation-only firmware tier was acknowledged.
    pub documentation_tier_acknowledged: bool,
}

impl PresetPlan {
    /// Returns true when every item is resolved and buildable.
    #[inline]
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.items.iter().all(|item| {
            !matches!(
                item.disposition,
                Disposition::NeedsInput | Disposition::Conflict
            )
        })
    }
}

/// Preset planning refusal.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum PresetPlanError {
    /// The target firmware precedes the captured preset firmware.
    #[error("target firmware is older than the captured preset firmware")]
    TargetFirmwareOlder,
    /// The target firmware line is not supported.
    #[error("target firmware is unsupported")]
    UnsupportedFirmware,
    /// Documentation-only target support was not acknowledged.
    #[error("documentation-tier target requires acknowledgement")]
    DocumentationTierAcknowledgementRequired,
    /// Captured firmware metadata is malformed.
    #[error("captured preset firmware version is invalid")]
    InvalidSourceFirmware,
}

/// Produces a pure preset plan without contacting either router.
///
/// # Errors
///
/// Returns [`PresetPlanError`] for incompatible firmware or a missing documentation-tier
/// acknowledgement. Unmapped objects and realm-bound passwords remain visible as plan inputs.
#[inline]
pub fn plan(
    preset: &Preset,
    target: &TargetInventory,
    mode: PresetMode,
    maps: &MigrationMaps,
    choices: &Choices,
) -> Result<PresetPlan, PresetPlanError> {
    let source_firmware = FirmwareVersion::from_str(&preset.source.firmware_version)
        .map_err(|_error| PresetPlanError::InvalidSourceFirmware)?;
    let target_firmware = target
        .info
        .firmware
        .ok_or(PresetPlanError::UnsupportedFirmware)?;
    if target_firmware < source_firmware {
        return Err(PresetPlanError::TargetFirmwareOlder);
    }
    match target.info.support_tier() {
        SupportTier::HardwareVerified => {}
        SupportTier::DocumentationBased if choices.ack_documentation_tier => {}
        SupportTier::DocumentationBased => {
            return Err(PresetPlanError::DocumentationTierAcknowledgementRequired);
        }
        SupportTier::Unsupported | _ => return Err(PresetPlanError::UnsupportedFirmware),
    }

    let mappings = classify::mapping_table(maps);
    let target_lines = flatten(&target.running_config);
    let target_text = target_lines
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    let source_items = preset.lines.iter().enumerate().map(|(index, line)| {
        classify::source_item(
            index,
            line,
            preset,
            target,
            &mappings,
            choices,
            &target_text,
        )
    });
    let mut items = source_items.collect::<Vec<_>>();
    if matches!(mode, PresetMode::Mirror) {
        let groups = super::groups::SettingsGroupEngine::embedded()
            .and_then(super::groups::SettingsGroupEngine::groups)
            .unwrap_or_default();
        let selected = groups
            .iter()
            .filter(|group| preset.groups.contains(&group.id))
            .flat_map(|group| group.include.iter());
        let source_text = items
            .iter()
            .filter_map(PresetPlanItem::expose_result)
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let removals = target_lines.iter().filter(|line| {
            let words = super::selection::words(line);
            selected
                .clone()
                .any(|pattern| super::glob::matches(pattern, &words))
                && !source_text.contains(&line.to_string())
        });
        for line in removals {
            let command = format!("no {line}");
            let buildable = apply::supports_line(&target.catalog, &command);
            items.push(PresetPlanItem {
                index: items.len(),
                disposition: if buildable {
                    Disposition::Remap
                } else {
                    Disposition::Unsupported
                },
                command: buildable.then(|| SecretString::from(command)),
                result: None,
                needed_input: None,
                reason: if buildable {
                    "preset-mirror-remove"
                } else {
                    "preset-unsupported"
                }
                .to_owned(),
            });
        }
    }
    Ok(PresetPlan {
        mode,
        items,
        documentation_tier_acknowledged: choices.ack_documentation_tier,
    })
}
