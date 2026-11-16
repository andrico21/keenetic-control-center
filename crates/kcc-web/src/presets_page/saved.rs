//! The presets kcc keeps.
//!
//! The encrypted preset store sits beside the backups; a copy run's transient preset is
//! sealed in the run's directory until the run finishes or a day passes without a change.

use kcc_config::config_text::parse;
use kcc_migrate::presets::{
    groups::SettingsGroupEngine,
    model::{CaptureRequest, Preset, PresetSource},
    payload::{LineText, secret_json, zeroizing_lines},
    store::PresetStore,
};
use secrecy::{ExposeSecret as _, SecretString, zeroize::Zeroizing};
use serde::{Deserialize, Serialize};

use crate::{
    fleet::Fleet,
    wizard::{
        services::Services,
        store::{Sealed, StoreError},
    },
};

/// The preset store of `fleet`'s state directory, sealed with the backups' key.
pub(super) fn store(fleet: &Fleet) -> PresetStore {
    let workflow = fleet.workflow();
    PresetStore::new(
        workflow.state().clone(),
        workflow.backups().key().duplicate(),
    )
}

/// A copy run's transient preset as opened: everything but its id and name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transient {
    /// Dependency-closed group ids.
    groups: Vec<String>,
    /// Source facts.
    source: PresetSource,
    /// The copied settings' command text.
    #[serde(deserialize_with = "zeroizing_lines")]
    lines: Zeroizing<Vec<String>>,
    /// Who copied them.
    created_by: String,
}

/// The fields of [`Transient`], borrowed from the preset being sealed.
#[derive(Serialize)]
struct Sealing<'preset> {
    /// Dependency-closed group ids.
    groups: &'preset [String],
    /// Source facts.
    source: &'preset PresetSource,
    /// The copied settings' command text.
    lines: LineText<'preset>,
    /// Who copied them.
    created_by: &'preset str,
}

/// Seals `preset` as the transient preset of run `id`.
///
/// # Errors
///
/// Returns sealing and write failures.
pub(super) fn seal(services: Services<'_>, id: &str, preset: &Preset) -> Result<(), StoreError> {
    let text = secret_json(&Sealing {
        groups: &preset.groups,
        source: &preset.source,
        lines: LineText::new(&preset.lines),
        created_by: &preset.created_by,
    })
    .map_err(|_error| StoreError::Malformed)?;
    services
        .store()
        .seal(services.key(), id, Sealed::Preset, &text)
}

/// The transient preset of run `id`, named `name`, while it is still sealed.
///
/// # Errors
///
/// Returns read, opening and format failures.
pub(super) fn transient(
    services: Services<'_>,
    id: &str,
    name: String,
) -> Result<Option<Preset>, StoreError> {
    let Some(sealed) = services.store().open(services.key(), id, Sealed::Preset)? else {
        return Ok(None);
    };
    let payload: Transient =
        serde_json::from_str(sealed.expose_secret()).map_err(|_error| StoreError::Malformed)?;
    let text = SecretString::from(payload.lines.join("\n"));
    let ast = parse(text.expose_secret()).map_err(|_error| StoreError::Malformed)?;
    let groups = payload
        .groups
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let selection = SettingsGroupEngine::embedded()
        .and_then(|engine| engine.select(&ast, &groups))
        .map_err(|_error| StoreError::Malformed)?;
    let request = CaptureRequest::new(
        id.to_owned(),
        name,
        String::new(),
        payload.groups,
        payload.source,
        payload.created_by,
    );
    Ok(Some(Preset::captured(request, selection)))
}
