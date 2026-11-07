//! The kinds a preset run's record names: its steps, where its settings come from, how
//! the router's own settings are treated, and how the run finished.

use kcc_i18n::{bundle::MessageKey, keys};
use kcc_migrate::presets::plan::PresetMode;
use serde::{Deserialize, Serialize};

/// One step of the apply wizard, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Step {
    /// The source router and groups of a copy; a preset's source is fixed.
    Source,
    /// The router the settings go to, and that router's warnings.
    Target,
    /// Merge or Mirror, the WireGuard keys and the names on the router.
    Options,
    /// Every setting and what happens to it.
    Review,
    /// The passwords the plan needs.
    Inputs,
    /// The ordered commands.
    Preview,
    /// The apply job, followed live.
    Apply,
    /// The verified result and the choice: keep unsaved, save or roll back.
    Results,
    /// The report of the finished run.
    Report,
}

impl Step {
    /// Every step in order.
    pub(super) const ALL: [Self; 9] = [
        Self::Source,
        Self::Target,
        Self::Options,
        Self::Review,
        Self::Inputs,
        Self::Preview,
        Self::Apply,
        Self::Results,
        Self::Report,
    ];

    /// The step's number, 1 to 9.
    pub(super) fn number(self) -> u32 {
        Self::ALL
            .iter()
            .position(|step| *step == self)
            .and_then(|index| u32::try_from(index).ok())
            .map_or(1, |index| index.saturating_add(1))
    }

    /// The step's name in forms, as serialized.
    pub(super) const fn slug(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Target => "target",
            Self::Options => "options",
            Self::Review => "review",
            Self::Inputs => "inputs",
            Self::Preview => "preview",
            Self::Apply => "apply",
            Self::Results => "results",
            Self::Report => "report",
        }
    }

    /// The step's name in the step list.
    pub(super) const fn label(self) -> MessageKey {
        match self {
            Self::Source => keys::WEB_PRESETS_STEP_SOURCE,
            Self::Target => keys::WEB_PRESETS_STEP_TARGET,
            Self::Options => keys::WEB_PRESETS_STEP_OPTIONS,
            Self::Review => keys::WEB_PRESETS_STEP_REVIEW,
            Self::Inputs => keys::WEB_PRESETS_STEP_INPUTS,
            Self::Preview => keys::WEB_PRESETS_STEP_PREVIEW,
            Self::Apply => keys::WEB_PRESETS_STEP_APPLY,
            Self::Results => keys::WEB_PRESETS_STEP_RESULTS,
            Self::Report => keys::WEB_PRESETS_STEP_REPORT,
        }
    }
}

/// Where a run's settings come from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(super) enum Origin {
    /// A saved preset.
    Preset {
        /// Preset id.
        id: String,
        /// Its name when the run started.
        name: String,
    },
    /// A one-off copy from a router: the copied settings are sealed beside the record.
    Copy,
}

/// What happens to the router's own settings in the settings' groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Mode {
    /// The settings are added or updated; the router keeps its own.
    #[default]
    Merge,
    /// As Merge, and the router's own settings in these groups that the settings lack
    /// are removed.
    Mirror,
}

impl Mode {
    /// The engine's mode.
    pub(super) const fn engine(self) -> PresetMode {
        match self {
            Self::Merge => PresetMode::Merge,
            Self::Mirror => PresetMode::Mirror,
        }
    }

    /// The mode's form value.
    pub(super) const fn slug(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Mirror => "mirror",
        }
    }
}

/// How a run finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Finish {
    /// The settings run on the router, unsaved.
    KeptUnsaved,
    /// The settings were saved on the router.
    Saved,
    /// kcc rolled the router back to its saved configuration.
    RolledBack,
    /// The router restored its saved configuration when its timer ran out.
    RolledBackByRouter,
    /// The apply ended without changes to keep: it failed before the first change, or
    /// kcc restarted while it ran.
    Closed,
}

impl Finish {
    /// The sentence saying how the run finished.
    pub(super) const fn text(self) -> MessageKey {
        match self {
            Self::KeptUnsaved => keys::WEB_PRESETS_FINISH_KEPT,
            Self::Saved => keys::WEB_PRESETS_FINISH_SAVED,
            Self::RolledBack => keys::WEB_PRESETS_FINISH_ROLLED_BACK,
            Self::RolledBackByRouter => keys::MIGRATE_APPLY_ROUTER_ROLLBACK,
            Self::Closed => keys::WEB_PRESETS_FINISH_CLOSED,
        }
    }

    /// The finish's name in the audit log and the report.
    pub(super) const fn slug(self) -> &'static str {
        match self {
            Self::KeptUnsaved => "kept-unsaved",
            Self::Saved => "saved",
            Self::RolledBack => "rolled-back",
            Self::RolledBackByRouter => "rolled-back-by-router",
            Self::Closed => "closed",
        }
    }
}
