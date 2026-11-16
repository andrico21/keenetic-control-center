//! The presets kcc keeps, and the sweep of old preset runs.
//!
//! The encrypted preset store sits beside the backups; a copy run's transient preset is
//! sealed in the run's directory until the run finishes or a day passed.

use kcc_config::config_text::parse;
use kcc_migrate::presets::{
    groups::SettingsGroupEngine,
    model::{CaptureRequest, Preset, PresetSource},
    payload::{LineText, secret_json, zeroizing_lines},
    store::PresetStore,
};
use secrecy::{ExposeSecret as _, SecretString, zeroize::Zeroizing};
use serde::{Deserialize, Serialize};

use super::{
    record::{FILE, Record},
    steps::Origin,
};
use crate::{
    fleet::Fleet,
    wizard::{
        flow::Flow as _,
        index, retention,
        services::Services,
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

/// Deletes what a run sealed: the copied settings and the typed passwords.
pub(super) fn discard(services: Services<'_>, id: &str) {
    let store = services.store();
    for part in [Sealed::Preset, Sealed::Passwords] {
        if let Err(error) = store.discard(id, part) {
            tracing::error!(%error, "preset run secrets could not be deleted");
        }
    }
}

/// Deletes, at `now`, the preset runs untouched for 30 days, and the sealed settings and
/// passwords of every copy run started more than a day before; such a run itself stays,
/// and says its settings are gone.
pub(super) fn sweep(services: Services<'_>, now: u64) {
    let store = services.store();
    retention::sweep::<Record>(&store, now);
    let runs = match index::runs::<Record>(&store) {
        Ok(found) => found,
        Err(error) => {
            tracing::warn!(%error, "preset runs could not be listed for expiry");
            return;
        }
    };
    for id in runs.into_keys() {
        if !store.sealed(&id, Sealed::Preset) && !store.sealed(&id, Sealed::Passwords) {
            continue;
        }
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
