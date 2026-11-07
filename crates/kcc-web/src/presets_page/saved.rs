//! The presets kcc keeps: the encrypted preset store beside the backups, and a copy run's
//! transient preset, sealed in the run's directory until the run finishes or a day passed.

use kcc_config::config_text::parse;
use kcc_migrate::presets::{
    groups::SettingsGroupEngine,
    model::{CaptureRequest, Preset, PresetSource},
    store::PresetStore,
};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};

use super::{
    record::{FILE, Record},
    steps::Origin,
};
use crate::{
    fleet::Fleet,
    migrate_wizard::{
        access::Services,
        store::{Sealed, StoreError},
    },
};

/// How long a copy run keeps its copied settings, in seconds.
const TRANSIENT_SECONDS: u64 = 24 * 60 * 60;

/// The preset store of `fleet`'s state directory, sealed with the backups' key.
pub(super) fn store(fleet: &Fleet) -> PresetStore {
    let workflow = fleet.workflow();
    PresetStore::new(
        workflow.state().clone(),
        workflow.backups().key().duplicate(),
    )
}

/// A copy run's transient preset as sealed: everything but its id and name.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transient {
    /// Dependency-closed group ids.
    groups: Vec<String>,
    /// Source facts.
    source: PresetSource,
    /// The copied settings' command text.
    lines: Vec<String>,
    /// Who copied them.
    created_by: String,
}

/// Seals `preset` as the transient preset of run `id`.
///
/// # Errors
///
/// Returns sealing and write failures.
pub(super) fn seal(services: Services<'_>, id: &str, preset: &Preset) -> Result<(), StoreError> {
    let payload = Transient {
        groups: preset.groups.clone(),
        source: preset.source.clone(),
        lines: preset.lines.iter().map(ToString::to_string).collect(),
        created_by: preset.created_by.clone(),
    };
    let text = SecretString::from(
        serde_json::to_string(&payload).map_err(|_error| StoreError::Malformed)?,
    );
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

/// Deletes what a run sealed: the copied settings and the typed passwords.
pub(super) fn discard(services: Services<'_>, id: &str) {
    let store = services.store();
    for part in [Sealed::Preset, Sealed::Passwords] {
        if let Err(error) = store.discard(id, part) {
            tracing::error!(%error, "preset run secrets could not be deleted");
        }
    }
}

/// Deletes the sealed settings and passwords of every copy run started more than a day
/// before `now`; the run itself stays, and says its settings are gone.
pub(super) fn sweep(services: Services<'_>, now: u64) {
    let store = services.store();
    let ids = match store.ids() {
        Ok(found) => found,
        Err(error) => {
            tracing::warn!(%error, "preset runs could not be listed for expiry");
            return;
        }
    };
    for id in ids {
        let expired = store
            .load_named::<Record>(&id, FILE)
            .ok()
            .flatten()
            .is_some_and(|record| {
                *record.origin() == Origin::Copy
                    && record.created_at().saturating_add(TRANSIENT_SECONDS) < now
            });
        if expired {
            discard(services, &id);
        }
    }
}
