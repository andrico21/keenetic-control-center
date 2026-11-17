//! Why a preset item has its treatment, as a type a caller matches exhaustively.

use core::fmt;

use serde::Serialize;

/// Why a preset plan item has its disposition.
///
/// The key ([`PresetReason::key`]) is the stable machine name in plans, reports and tool
/// results.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
#[expect(
    clippy::exhaustive_enums,
    reason = "callers must match every reason; a new one has to break their build"
)]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers read it beside the migration's `rules::reason::Reason`"
)]
pub enum PresetReason {
    /// The line is sent to the target.
    #[serde(rename = "preset-add")]
    Add,
    /// The target already has the line; nothing is sent.
    #[serde(rename = "preset-already-present")]
    AlreadyPresent,
    /// Mirror mode removes the target-only line.
    #[serde(rename = "preset-mirror-remove")]
    MirrorRemove,
    /// The target's catalog cannot build the line.
    #[serde(rename = "preset-unsupported")]
    Unsupported,
    /// The line waits for an operator input.
    #[serde(rename = "preset-needs-input")]
    NeedsInput,
}

impl PresetReason {
    /// The reason's stable machine name, such as `preset-add`.
    #[inline]
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Add => "preset-add",
            Self::AlreadyPresent => "preset-already-present",
            Self::MirrorRemove => "preset-mirror-remove",
            Self::Unsupported => "preset-unsupported",
            Self::NeedsInput => "preset-needs-input",
        }
    }
}

impl fmt::Display for PresetReason {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.key())
    }
}
