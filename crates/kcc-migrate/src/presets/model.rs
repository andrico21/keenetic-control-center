//! Preset value types and capture input.

use core::fmt;

use kcc_config::{
    config_text::{CliLine, Token, flatten, parse},
    secrets::redact,
};
use serde::{Deserialize, Serialize};

use super::groups::GroupSelection;

/// Origin from which a preset was captured.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum PresetSourceKind {
    /// A registered router.
    Router,
    /// An encrypted backup.
    Backup,
    /// An uploaded configuration file.
    File,
}

/// Immutable source facts recorded at capture time.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct PresetSource {
    /// Source category.
    pub kind: PresetSourceKind,
    /// Registered router id when the source is router-scoped.
    pub router_id: Option<String>,
    /// Source model or hardware id.
    pub model: String,
    /// Source firmware version as advertised during capture.
    pub firmware_version: String,
    /// Injected Unix timestamp of capture.
    pub captured_at: u64,
}

impl PresetSource {
    /// Records source facts for a preset capture.
    #[inline]
    #[must_use]
    pub const fn new(
        kind: PresetSourceKind,
        router_id: Option<String>,
        model: String,
        firmware_version: String,
        captured_at: u64,
    ) -> Self {
        Self {
            kind,
            router_id,
            model,
            firmware_version,
            captured_at,
        }
    }
}

/// Captured, dependency-closed settings preset.
#[non_exhaustive]
pub struct Preset {
    /// Stable file-safe preset id.
    pub id: String,
    /// Operator-visible name.
    pub name: String,
    /// Operator-visible description.
    pub description: String,
    /// Selected group ids after group dependency closure.
    pub groups: Vec<String>,
    /// Source facts used for authorization and compatibility checks.
    pub source: PresetSource,
    /// Source-ordered, dependency-closed command lines.
    pub lines: Vec<CliLine>,
    /// Stable creator identity.
    pub created_by: String,
}

impl Clone for Preset {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            groups: self.groups.clone(),
            source: self.source.clone(),
            lines: self.lines.clone(),
            created_by: self.created_by.clone(),
        }
    }
}

impl fmt::Debug for Preset {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            id,
            name,
            description,
            groups,
            source,
            lines: _,
            created_by,
        } = self;
        f.debug_struct("Preset")
            .field("id", id)
            .field("name", name)
            .field("description", description)
            .field("groups", groups)
            .field("source", source)
            .field("lines", &"[REDACTED]")
            .field("created_by", created_by)
            .finish()
    }
}

/// Validated values used to capture a preset.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CaptureRequest {
    /// Caller-selected stable id.
    pub id: String,
    /// Operator-visible name.
    pub name: String,
    /// Operator-visible description.
    pub description: String,
    /// Requested group ids.
    pub groups: Vec<String>,
    /// Source facts.
    pub source: PresetSource,
    /// Creator identity.
    pub created_by: String,
}

impl CaptureRequest {
    /// Defines one preset capture request.
    #[inline]
    #[must_use]
    pub const fn new(
        id: String,
        name: String,
        description: String,
        groups: Vec<String>,
        source: PresetSource,
        created_by: String,
    ) -> Self {
        Self {
            id,
            name,
            description,
            groups,
            source,
            created_by,
        }
    }
}

impl Preset {
    /// Builds a captured preset from an already dependency-closed selection.
    #[inline]
    #[must_use]
    pub fn captured(request: CaptureRequest, selection: GroupSelection) -> Self {
        let CaptureRequest {
            id,
            name,
            description,
            groups: _,
            source,
            created_by,
        } = request;
        Self {
            id,
            name,
            description,
            groups: selection.groups,
            source,
            lines: selection.lines,
            created_by,
        }
    }

    /// Returns a copy whose secret-bearing command tokens are redacted.
    #[inline]
    #[must_use]
    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        let text = self
            .lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        redacted.lines = parse(&text).map_or_default(|ast| flatten(&redact(&ast)));
        for token in redacted
            .lines
            .iter_mut()
            .flat_map(|line| line.tokens.iter_mut())
        {
            if let Token::Ns3(payload) = token {
                "<redacted>".clone_into(payload);
            }
        }
        redacted
    }

    /// Returns true when the source is bound to `router`.
    #[inline]
    #[must_use]
    pub fn source_router(&self) -> Option<&str> {
        self.source.router_id.as_deref()
    }

    /// Returns command text for encrypted persistence only.
    pub(super) fn command_text(&self) -> Vec<String> {
        self.lines.iter().map(ToString::to_string).collect()
    }

    /// Replaces command lines after decrypting a persisted record.
    pub(super) fn with_lines(mut self, lines: Vec<CliLine>) -> Self {
        self.lines = lines;
        self
    }
}

/// Builds a single flattened line from persisted command text.
pub(super) fn parse_line(text: &str) -> Option<CliLine> {
    let ast = parse(text).ok()?;
    let mut lines = flatten(&ast).into_iter();
    match (lines.next(), lines.next()) {
        (Some(line), None) => Some(line),
        (None, None | Some(_)) | (Some(_), Some(_)) => None,
    }
}
