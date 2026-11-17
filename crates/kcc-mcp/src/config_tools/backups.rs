//! `kcc_backup_create`, `kcc_backup_list`, and `kcc_backup_diff` with secrets redacted.

use kcc_app::{backups::BackupError, permissions::Permission};
use kcc_config::{
    config_text::{flatten, parse},
    mask::redacted_config,
};
use kcc_rci::ConfigKind;
use schemars::JsonSchema;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    KccMcp, McpFailure,
    support::{
        audit::Success, errors::map_rci, route::parse as parse_arguments, validate::valid_text,
    },
};

/// Longest backup file name.
const MAX_NAME_CHARS: usize = 96;

/// Arguments of the single-router configuration and backup tools.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouterInput {
    /// Router profile id.
    host: String,
}

impl RouterInput {
    /// Returns the requested router profile id.
    pub(crate) fn into_host(self) -> String {
        self.host
    }
}

/// Arguments of `kcc_backup_diff`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiffInput {
    /// Router profile id.
    host: String,
    /// Older backup file name.
    from: String,
    /// Newer backup file name.
    to: String,
}

/// Maps a backup store failure.
fn map_backup(error: &BackupError) -> McpFailure {
    tracing::warn!(error = ?error, "MCP backup operation failed");
    match error {
        BackupError::NotFound { name: _ } | BackupError::InvalidName { value: _ } => {
            McpFailure::InvalidArguments
        }
        BackupError::State(_)
        | BackupError::Crypto(_)
        | BackupError::Malformed { name: _ }
        | BackupError::Config(_)
        | _ => McpFailure::Internal,
    }
}

/// Stores the router's startup configuration as an encrypted backup.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) async fn create(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: RouterInput = parse_arguments(arguments)?;
    let (_identity, router) = server.authorize_host(Permission::Write, input.into_host())?;
    let client = server
        .registry
        .client(router.as_str())
        .await
        .map_err(|_error| McpFailure::RouterUnreachable)?;
    let bytes = client
        .download_config(ConfigKind::Startup)
        .await
        .map_err(|error| map_rci(&error))?;
    let text = SecretString::from(
        str::from_utf8(bytes.expose_secret())
            .map_err(|_error| McpFailure::ValidationFailed)?
            .to_owned(),
    );
    let info = server
        .workflow
        .backups()
        .create(router.as_str(), "mcp", &text)
        .map_err(|error| map_backup(&error))?;
    let result = json!({ "name": info.name, "created_at": info.created_at, "reason": info.reason });
    Ok(Success::new("kcc_backup_create")
        .on_router(router.as_str())
        .with_target(info.name)
        .record(server, result)
        .await)
}

/// Lists the router's backups, newest first.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) fn list(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: RouterInput = parse_arguments(arguments)?;
    let (_identity, router) = server.authorize_host(Permission::Read, input.into_host())?;
    let backups = server
        .workflow
        .backups()
        .list(router.as_str())
        .map_err(|error| map_backup(&error))?
        .into_iter()
        .map(|info| json!({ "name": info.name, "created_at": info.created_at, "reason": info.reason }))
        .collect::<Vec<_>>();
    Ok(json!({ "backups": backups }))
}

/// Diffs two backups line by line; changed secrets show as changed redacted lines.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
pub(crate) fn diff(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: DiffInput = parse_arguments(arguments)?;
    valid_text(&input.from, MAX_NAME_CHARS)?;
    valid_text(&input.to, MAX_NAME_CHARS)?;
    let (_identity, router) = server.authorize_host(Permission::Read, input.host)?;
    let store = server.workflow.backups();
    let older = lines(
        &store
            .get(router.as_str(), &input.from)
            .map_err(|error| map_backup(&error))?,
    )?;
    let newer = lines(
        &store
            .get(router.as_str(), &input.to)
            .map_err(|error| map_backup(&error))?,
    )?;
    Ok(json!({
        "from": input.from,
        "to": input.to,
        "removed": only_in(&older, &newer),
        "added": only_in(&newer, &older)
    }))
}

/// Each flattened command: its complete text (secret) and its redacted display.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn lines(text: &SecretString) -> Result<Vec<(SecretString, String)>, McpFailure> {
    let ast = parse(text.expose_secret()).map_err(|_error| McpFailure::ValidationFailed)?;
    let shown = flatten(&redacted_config(&ast))
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    Ok(flatten(&ast)
        .iter()
        .map(|line| SecretString::from(line.to_string()))
        .zip(shown)
        .collect())
}

/// Redacted display lines of `left` whose complete text is absent from `right`.
fn only_in(left: &[(SecretString, String)], right: &[(SecretString, String)]) -> Vec<String> {
    left.iter()
        .filter(|(full, _shown)| {
            !right
                .iter()
                .any(|(other, _other_shown)| other.expose_secret() == full.expose_secret())
        })
        .map(|(_full, shown)| shown.clone())
        .collect()
}
