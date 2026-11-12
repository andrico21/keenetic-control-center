//! What a migration works on: its parsed source configuration and the target router's
//! read-only inventory.
//!
//! Collecting reads the target (identity, both configurations, components, agreements,
//! the authentication realm) through a migration client of the registry; nothing is
//! written. Classification and the leftover list are computed from these in memory.

use alloc::collections::{BTreeMap, BTreeSet};
use core::str::FromStr as _;

use kcc_app::permissions::Role;
use kcc_config::{
    config_text::{CliLine, Token, flatten},
    secrets::redact,
};
use kcc_migrate::{
    inventory::{InventoryClient, InventoryError, TargetInventory},
    planner::{Choices, Planner},
    rules::{ClassifiedItem, RuleError},
    source::SourceConfig,
};
use kcc_rci::{RciBody, RciClient, RciError, RciPath, version::FirmwareVersion};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::Value;

use super::{kinds::Maps, plan::engine_maps, record::Record};
use crate::fleet::Fleet;

/// What `<redacted>` stands for in a shown line.
const REDACTED: &str = "<redacted>";

/// Why the analysis could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Problem {
    /// The source configuration cannot be read.
    Source,
    /// The source names no firmware, and none was typed in.
    FirmwareRequired,
    /// The target runs older firmware than the source.
    FirmwareOlder {
        /// The source's firmware.
        source: String,
        /// The target's firmware.
        target: String,
    },
    /// The target's firmware is below 4.3 or unknown.
    Unsupported,
    /// The target did not answer.
    Unreachable,
}

/// One agreement the target asks to accept before its configuration changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Agreement {
    /// `dpn` or `eula`.
    name: &'static str,
    /// The document's current text.
    text: String,
}

impl Agreement {
    /// `dpn` or `eula`.
    pub(super) const fn name(&self) -> &'static str {
        self.name
    }

    /// The document's current text.
    pub(super) fn text(&self) -> &str {
        &self.text
    }
}

/// The source and target of one migration.
pub(super) struct Analysis {
    /// The parsed source configuration.
    source: SourceConfig,
    /// The target's inventory.
    target: TargetInventory,
    /// Agreements the target asks to accept.
    agreements: Vec<Agreement>,
}

impl Analysis {
    /// Parses `source_text` and reads the record's target as `role`.
    ///
    /// # Errors
    ///
    /// Returns why the source or the target cannot be used.
    // cancel-safe: every router operation is a read.
    pub(super) async fn collect(
        fleet: &Fleet,
        role: &Role,
        record: &Record,
        source_text: &SecretString,
    ) -> Result<Self, Problem> {
        let source = parse_source(source_text)?;
        let typed = record
            .source_firmware()
            .and_then(|text| FirmwareVersion::from_str(text).ok());
        let firmware = source.firmware_or(typed).ok_or(Problem::FirmwareRequired)?;
        let target_id = record.target().ok_or(Problem::Unreachable)?;
        let client = fleet
            .registry()
            .bootstrap_client(role, target_id)
            .await
            .map_err(|error| {
                tracing::warn!(%error, router = target_id, "migration target: no client");
                Problem::Unreachable
            })?;
        let target =
            TargetInventory::collect(&InventoryClient::from_client(&client), Some(firmware))
                .await
                .map_err(|error| inventory_problem(&error))?;
        let agreements = pending_agreements(&client).await?;
        Ok(Self {
            source,
            target,
            agreements,
        })
    }

    /// The parsed source configuration.
    pub(super) const fn source(&self) -> &SourceConfig {
        &self.source
    }

    /// The target's inventory.
    pub(super) const fn target(&self) -> &TargetInventory {
        &self.target
    }

    /// Agreements the target asks to accept.
    pub(super) fn agreements(&self) -> &[Agreement] {
        &self.agreements
    }

    /// Every source line classified with `maps`, the typed `passwords` and the conflicts
    /// whose source values `overwrite` takes, as the plan classifies it: lines the target
    /// cannot build are unsupported.
    ///
    /// # Errors
    ///
    /// Returns a malformed embedded rule set.
    pub(super) fn classify(
        &self,
        maps: &Maps,
        passwords: &BTreeMap<String, SecretString>,
        overwrite: &BTreeSet<String>,
    ) -> Result<Vec<ClassifiedItem>, RuleError> {
        let mut choices = Choices::default();
        passwords.clone_into(&mut choices.new_passwords);
        overwrite.clone_into(&mut choices.overwrite_scalars);
        Planner::classify(&self.source, &self.target, &engine_maps(maps), &choices)
    }

    /// The target's settings the source does not have, redacted: they stay on the target
    /// after the migration.
    pub(super) fn leftovers(&self) -> Vec<String> {
        let source = flatten(&self.source.ast)
            .iter()
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let running = &self.target.running_config;
        flatten(running)
            .iter()
            .zip(flatten(&redact(running)))
            .filter(|(line, _)| !source.contains(&line.to_string()))
            .map(|(_, shown)| shown_line(shown))
            .collect()
    }
}

/// `line` with every encoded secret replaced, as the review shows it.
pub(crate) fn shown_line(mut line: CliLine) -> String {
    for token in &mut line.tokens {
        if let Token::Ns3(payload) = token {
            REDACTED.clone_into(payload);
        }
    }
    line.to_string()
}

/// The source configuration in `text`.
///
/// # Errors
///
/// Returns [`Problem::Source`] when it does not parse or its checksum does not match.
pub(crate) fn parse_source(text: &SecretString) -> Result<SourceConfig, Problem> {
    SourceConfig::from_bytes(text.expose_secret().as_bytes()).map_err(|_error| Problem::Source)
}

/// The problem an inventory failure means.
pub(crate) fn inventory_problem(error: &InventoryError) -> Problem {
    match error {
        InventoryError::SourceVersionRequired => Problem::FirmwareRequired,
        InventoryError::TargetFirmwareOlder {
            source_version,
            target_version,
        } => Problem::FirmwareOlder {
            source: source_version.to_string(),
            target: target_version.to_string(),
        },
        InventoryError::UnsupportedFirmware | InventoryError::Catalog => Problem::Unsupported,
        other @ (InventoryError::Rci(_)
        | InventoryError::ConfigEncoding
        | InventoryError::Parse(_)
        | _) => {
            tracing::warn!(error = %other, "migration target inventory failed");
            Problem::Unreachable
        }
    }
}

/// The agreements the target has not accepted, with their current text.
///
/// # Errors
///
/// Returns [`Problem::Unreachable`] when the router does not answer.
// cancel-safe: reads only.
async fn pending_agreements(client: &RciClient) -> Result<Vec<Agreement>, Problem> {
    let mut pending = Vec::new();
    for name in ["dpn", "eula"] {
        let Some(list) = read(client, ["show", name, "list"]).await? else {
            continue;
        };
        if list.get("accepted").and_then(Value::as_bool) == Some(true) {
            continue;
        }
        let text = read(client, ["show", name, "document"])
            .await?
            .and_then(|document| {
                document
                    .get("text")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        pending.push(Agreement { name, text });
    }
    Ok(pending)
}

/// The JSON answer of `segments`, or `None` when the router does not have it.
///
/// # Errors
///
/// Returns [`Problem::Unreachable`] when the router does not answer.
// cancel-safe: a read.
async fn read(client: &RciClient, segments: [&str; 3]) -> Result<Option<Value>, Problem> {
    let path = RciPath::from_segments(segments).map_err(|_error| Problem::Unreachable)?;
    match client.get(&path, &()).await {
        Ok(RciBody::Json(response)) => Ok(Some(response.value)),
        Ok(_) | Err(RciError::NotFound | RciError::MethodNotAllowed) => Ok(None),
        Err(error) => {
            tracing::warn!(%error, "migration target agreement read failed");
            Err(Problem::Unreachable)
        }
    }
}
