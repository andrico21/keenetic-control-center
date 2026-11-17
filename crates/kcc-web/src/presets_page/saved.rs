//! The presets kcc keeps.
//!
//! The encrypted preset store sits beside the backups; a copy run's transient preset is
//! sealed in the run's directory until the run finishes or a day passes without a change.

use kcc_app::permissions::Role;
use kcc_config::config_text::{Ast, parse};
use kcc_migrate::presets::{
    groups::SettingsGroupEngine,
    model::{CaptureRequest, Preset, PresetSource},
    payload::{LineText, secret_json, zeroizing_lines},
    store::{PresetError, PresetStore},
};
use secrecy::{ExposeSecret as _, SecretString, zeroize::Zeroizing};
use serde::{Deserialize, Serialize};

use crate::{
    blocking,
    fleet::Fleet,
    wizard::{
        services::Services,
        store::{Sealed, StoreError},
    },
};

/// Runs `work` on the preset store of `fleet` on the blocking pool: the store reads,
/// writes and seals files.
///
/// # Errors
///
/// Returns the error of `work`, or an I/O error when the task did not finish.
// NOT cancel-safe: dropped, `work` still runs to its end on the blocking pool.
async fn on_store<T, W>(fleet: &Fleet, work: W) -> Result<T, PresetError>
where
    W: FnOnce(&PresetStore) -> Result<T, PresetError> + Send + 'static,
    T: Send + 'static,
{
    let presets = store(fleet);
    blocking::run(move || work(&presets), PresetError::Io).await
}

/// The saved presets `role` sees, redacted (see [`PresetStore::list`]).
///
/// # Errors
///
/// Returns permission and directory failures.
// cancel-safe: reads only.
pub(super) async fn list(fleet: &Fleet, role: &Role) -> Result<Vec<Preset>, PresetError> {
    let reader = role.clone();
    on_store(fleet, move |presets| presets.list(&reader)).await
}

/// Preset `id` as `role` may see it (see [`PresetStore::get`]).
///
/// # Errors
///
/// Returns permission, missing-record, opening and read failures.
// cancel-safe: reads only.
pub(super) async fn get(fleet: &Fleet, role: &Role, id: &str) -> Result<Preset, PresetError> {
    let (reader, preset) = (role.clone(), id.to_owned());
    on_store(fleet, move |presets| presets.get(&reader, &preset)).await
}

/// Preset `id` with its secrets, to plan and apply it (see
/// [`PresetStore::load_for_apply`]).
///
/// # Errors
///
/// Returns permission, missing-record, opening and read failures.
// cancel-safe: reads only.
pub(super) async fn load_for_apply(
    fleet: &Fleet,
    role: &Role,
    id: &str,
) -> Result<Preset, PresetError> {
    let (reader, preset) = (role.clone(), id.to_owned());
    on_store(fleet, move |presets| {
        presets.load_for_apply(&reader, &preset)
    })
    .await
}

/// Deletes preset `id` (see [`PresetStore::delete`]).
///
/// # Errors
///
/// Returns permission, missing-record, lock and removal failures.
// NOT cancel-safe: dropped, the preset is still deleted.
pub(super) async fn delete(fleet: &Fleet, role: &Role, id: &str) -> Result<(), PresetError> {
    let (deleter, preset) = (role.clone(), id.to_owned());
    on_store(fleet, move |presets| presets.delete(&deleter, &preset)).await
}

/// Captures and stores the preset `request` asks for from `source` (see
/// [`PresetStore::capture`]).
///
/// # Errors
///
/// Returns permission, selection, sealing and write failures.
// NOT cancel-safe: dropped, the preset is still stored.
pub(super) async fn capture(
    fleet: &Fleet,
    role: &Role,
    source: Ast,
    request: CaptureRequest,
) -> Result<Preset, PresetError> {
    let capturer = role.clone();
    on_store(fleet, move |presets| {
        presets.capture(&capturer, &source, request)
    })
    .await
}

/// The preset store of `fleet`'s state directory, sealed with the backups' key.
fn store(fleet: &Fleet) -> PresetStore {
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
// NOT cancel-safe: dropped, the sealed preset is still written.
pub(super) async fn seal(
    services: Services<'_>,
    id: &str,
    preset: &Preset,
) -> Result<(), StoreError> {
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
        .await
}

/// The transient preset of run `id`, named `name`, while it is still sealed.
///
/// # Errors
///
/// Returns read, opening and format failures.
// cancel-safe: reads only.
pub(super) async fn transient(
    services: Services<'_>,
    id: &str,
    name: String,
) -> Result<Option<Preset>, StoreError> {
    let Some(sealed) = services
        .store()
        .open(services.key(), id, Sealed::Preset)
        .await?
    else {
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
