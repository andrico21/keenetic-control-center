//! `kcc_preset_capture`: capture settings groups from a router or one of its backups.

use alloc::sync::Arc;
use core::slice::from_ref;
use std::time::{SystemTime, UNIX_EPOCH};

use kcc_app::permissions::Permission;
use kcc_migrate::{
    presets::{
        groups::SettingsGroupEngine,
        model::{CaptureRequest, Preset, PresetSource, PresetSourceKind},
    },
    source::SourceConfig,
};
use kcc_rci::ConfigKind;
use schemars::JsonSchema;
use secrecy::ExposeSecret as _;
use serde::Deserialize;
use serde_json::{Value, json};

use super::state::{map_preset, view};
use crate::{
    KccMcp, McpFailure, RouterId, authorize_routers,
    support::{audit::Success, blocking, errors::map_rci, route::parse, validate::valid_text},
};

/// Most settings groups in one capture.
const MAX_GROUPS: usize = 32;

/// Arguments of `kcc_preset_capture`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CaptureInput {
    /// Source router profile id; its startup configuration is captured.
    #[serde(default)]
    source: Option<String>,
    /// Source backup as `<router id>/<backup file name>` (instead of `source`).
    #[serde(default)]
    backup: Option<String>,
    /// Settings group ids, e.g. `dns-secure`; dependencies are added automatically.
    groups: Vec<String>,
    /// Preset name; its lowercase slug becomes the stored preset id.
    name: String,
    /// Optional description.
    #[serde(default)]
    description: String,
    /// Keep a one-off copy in memory for `kcc_preset_apply` instead of storing it.
    #[serde(default)]
    transient: bool,
}

/// Where the captured configuration comes from.
enum Origin {
    /// A router's startup configuration.
    Router(RouterId),
    /// A backup of a router.
    Backup(RouterId, String),
}

impl Origin {
    /// Parses exactly one of `source` and `backup`.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    fn parse(source: Option<String>, backup: Option<String>) -> Result<Self, McpFailure> {
        match (source, backup) {
            (Some(router), None) => Ok(Self::Router(RouterId::new(router)?)),
            (None, Some(reference)) => {
                let (router, name) = reference
                    .split_once('/')
                    .ok_or(McpFailure::InvalidArguments)?;
                valid_text(name, 96)?;
                Ok(Self::Backup(
                    RouterId::new(router.to_owned())?,
                    name.to_owned(),
                ))
            }
            (None, None) | (Some(_), Some(_)) => Err(McpFailure::InvalidArguments),
        }
    }

    /// The router the source belongs to.
    const fn router(&self) -> &RouterId {
        match self {
            Self::Router(router) | Self::Backup(router, _) => router,
        }
    }
}

/// A file-safe id from a display name.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
fn slug(name: &str) -> Result<String, McpFailure> {
    let mut id = String::new();
    for character in name.trim().chars().flat_map(char::to_lowercase) {
        let kept = if character.is_ascii_alphanumeric() || character == '_' {
            Some(character)
        } else {
            (!id.ends_with('-')).then_some('-')
        };
        id.extend(kept);
    }
    let trimmed = id.trim_matches('-').to_owned();
    if trimmed.is_empty() || trimmed.len() > 64 {
        return Err(McpFailure::InvalidArguments);
    }
    Ok(trimmed)
}

/// Reads the source configuration after the caller's scope was checked.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: it only reads the router's startup configuration or a stored backup, but it may
// sign in first, and a sign-in dropped mid-way can leave an orphaned router session.
async fn read(server: &KccMcp, origin: &Origin) -> Result<SourceConfig, McpFailure> {
    let bytes = match origin {
        Origin::Router(router) => {
            let client = server
                .registry
                .client(router.as_str())
                .await
                .map_err(|_error| McpFailure::RouterUnreachable)?;
            let bytes = client
                .download_config(ConfigKind::Startup)
                .await
                .map_err(|error| map_rci(&error))?;
            bytes.expose_secret().to_vec()
        }
        Origin::Backup(router, name) => {
            let (backups, owner, backup) = (
                Arc::clone(server.workflow.backups()),
                router.as_str().to_owned(),
                name.clone(),
            );
            blocking::run(move || backups.get(&owner, &backup))
                .await?
                .map_err(|error| {
                    tracing::warn!(error = ?error, "MCP preset backup source unavailable");
                    McpFailure::InvalidArguments
                })?
                .expose_secret()
                .as_bytes()
                .to_vec()
        }
    };
    SourceConfig::from_bytes(&bytes).map_err(|_error| McpFailure::ValidationFailed)
}

/// Captures a preset; transient copies stay in memory and are never written to disk.
///
/// # Errors
///
/// Returns an `McpFailure` naming the refusal or failure to report to the client.
// NOT cancel-safe: the preset may be stored on the blocking pool, and its audit entry queued, after
// the future is dropped.
pub(crate) async fn capture(server: &KccMcp, arguments: Value) -> Result<Value, McpFailure> {
    let input: CaptureInput = parse(arguments)?;
    if input.groups.is_empty() || input.groups.len() > MAX_GROUPS {
        return Err(McpFailure::InvalidArguments);
    }
    for group in &input.groups {
        valid_text(group, 64)?;
    }
    valid_text(&input.name, 96)?;
    if !input.description.is_empty() {
        valid_text(&input.description, 512)?;
    }
    let origin = Origin::parse(input.source, input.backup)?;
    let identity = server.identity()?;
    authorize_routers(&identity, Permission::Migrate, from_ref(origin.router()))?;
    let presets = &server.presets;
    let (id, persistent) = if input.transient {
        (presets.transient_id(), false)
    } else {
        (slug(&input.name)?, presets.store().map(|_store| true)?)
    };
    let config = read(server, &origin).await?;
    let firmware = config
        .firmware
        .ok_or(McpFailure::ValidationFailed)?
        .to_string();
    let model = config
        .header
        .model
        .clone()
        .or_else(|| config.hw_id.clone())
        .unwrap_or_default();
    let kind = match origin {
        Origin::Router(_) => PresetSourceKind::Router,
        Origin::Backup(_, _) => PresetSourceKind::Backup,
    };
    let captured_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let source = PresetSource::new(
        kind,
        Some(origin.router().as_str().to_owned()),
        model,
        firmware,
        captured_at,
    );
    let request = CaptureRequest::new(
        id,
        input.name,
        input.description,
        input.groups,
        source,
        identity.name.clone(),
    );
    let done = Success::new("kcc_preset_capture")
        .on_router(origin.router().as_str())
        .with_target(request.id.clone());
    if persistent {
        let (role, ast) = (identity.role.clone(), config.ast);
        let stored = presets
            .stored(move |store| store.capture(&role, &ast, request))
            .await?
            .map_err(|error| map_preset(&error))?;
        let params = json!({ "id": stored.id, "groups": stored.groups });
        return Ok(done
            .with_params(params)
            .record(server, view(&stored, false))
            .await);
    }
    let selected = request
        .groups
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let selection = SettingsGroupEngine::embedded()
        .and_then(|engine| engine.select(&config.ast, &selected))
        .map_err(|_error| McpFailure::InvalidArguments)?;
    let preset = Preset::captured(request, selection);
    let value = view(&preset, true);
    let params = json!({ "id": preset.id, "groups": preset.groups, "transient": true });
    presets.keep(identity.name, preset).await;
    Ok(done.with_params(params).record(server, value).await)
}
