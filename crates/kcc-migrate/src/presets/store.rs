//! Encrypted preset capture and persistence.

use std::{fs, io, path::PathBuf};

use kcc_app::{
    permissions::{Permission, Role},
    persist::{StateError, StateLock, StateStore, create_private_dir, write_atomic},
    secrets::{CryptoError, MasterKey, SealedSecret, binding::Binding},
};
use kcc_config::config_text::Ast;
use secrecy::ExposeSecret as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use self::access::{
    authorize_any_source, authorize_source, require_permission, source_allowed, validate_id,
};
use super::{
    groups::{GroupError, SettingsGroupEngine},
    model::{CaptureRequest, Preset, PresetSource, parse_line},
    payload::{LineText, secret_json, zeroizing_lines},
};

mod access;

/// Current encrypted preset record schema.
const SCHEMA: u32 = 1;

/// Encrypted on-disk preset store.
#[derive(Debug)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public store type identifies the preset domain"
)]
pub struct PresetStore {
    /// State directory owning preset files and locks.
    state: StateStore,
    /// Application master key shared with encrypted backups.
    key: MasterKey,
}

/// Preset storage and authorization failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PresetError {
    /// The caller cannot use this preset or source.
    #[error("preset operation is forbidden")]
    Forbidden,
    /// The preset id is not file-safe.
    #[error("preset id is invalid")]
    InvalidId,
    /// The preset does not exist.
    #[error("preset was not found")]
    NotFound,
    /// The encrypted record is malformed or has an unsupported schema.
    #[error("preset record is malformed")]
    Malformed,
    /// Group selection failed.
    #[error(transparent)]
    Groups(#[from] GroupError),
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// Encryption failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// Preset file I/O failed.
    #[error("preset storage I/O failed")]
    Io(#[source] io::Error),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Plaintext envelope around an encrypted preset payload.
struct PresetRecord {
    /// Envelope schema.
    schema: u32,
    /// Authorization metadata required before decryption.
    source_router: Option<String>,
    /// Encrypted payload.
    sealed: SealedSecret,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
/// Complete payload protected by the master key, as opened.
struct PresetPayload {
    /// Stable preset id.
    id: String,
    /// Display name.
    name: String,
    /// Display description.
    description: String,
    /// Dependency-closed group ids.
    groups: Vec<String>,
    /// Captured source facts.
    source: PresetSource,
    /// Source-ordered command text.
    #[serde(deserialize_with = "zeroizing_lines")]
    lines: Zeroizing<Vec<String>>,
    /// Creator identity.
    created_by: String,
}

#[derive(Serialize)]
/// The payload of [`PresetPayload`], borrowed from the preset being sealed.
struct SealedPayload<'preset> {
    /// Stable preset id.
    id: &'preset str,
    /// Display name.
    name: &'preset str,
    /// Display description.
    description: &'preset str,
    /// Dependency-closed group ids.
    groups: &'preset [String],
    /// Captured source facts.
    source: &'preset PresetSource,
    /// Source-ordered command text.
    lines: LineText<'preset>,
    /// Creator identity.
    created_by: &'preset str,
}

impl PresetStore {
    /// Creates a preset store using the application's state directory and master key.
    #[inline]
    #[must_use]
    pub const fn new(state: StateStore, key: MasterKey) -> Self {
        Self { state, key }
    }

    /// Captures selected groups and persists the resulting preset encrypted at rest.
    ///
    /// A preset already stored under the id is replaced only when the caller holds
    /// `Migrate` on that preset's source router, the check [`delete`](Self::delete) makes.
    /// A stored record that cannot be read or decrypted names no source router to check,
    /// so only a caller whose scope covers every router may replace it. The check and the
    /// write happen under one lock.
    ///
    /// # Errors
    ///
    /// Returns authorization ([`PresetError::Forbidden`] also for a stored preset outside
    /// the caller's scope), group-selection, validation, encryption, or I/O errors.
    #[inline]
    pub fn capture(
        &self,
        role: &Role,
        source: &Ast,
        request: CaptureRequest,
    ) -> Result<Preset, PresetError> {
        validate_id(&request.id)?;
        authorize_source(role, request.source.router_id.as_deref())?;
        let selected = request
            .groups
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let selection = SettingsGroupEngine::embedded()?.select(source, &selected)?;
        let preset = Preset::captured(request, selection);
        let lock = self.state.lock("presets")?;
        self.authorize_replace(role, &preset.id)?;
        self.save(&preset, &lock)?;
        Ok(preset.redacted())
    }

    /// Lists metadata-visible presets whose router source is in the caller's scope.
    ///
    /// # Errors
    ///
    /// Returns permission or directory I/O errors. A record that cannot be read (I/O errors
    /// included), parsed or decrypted is skipped and its file name logged.
    #[inline]
    pub fn list(&self, role: &Role) -> Result<Vec<Preset>, PresetError> {
        require_permission(role, Permission::Read)?;
        let directory = self.directory();
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(PresetError::Io(error)),
        };
        let mut presets = Vec::new();
        for listed in entries {
            let entry = listed.map_err(PresetError::Io)?;
            let file_name = entry.file_name();
            let Some((name, id)) = file_name
                .to_str()
                .and_then(|name| Some((name, name.strip_suffix(".json")?)))
            else {
                continue;
            };
            let visible = read_record(entry.path()).and_then(|record| {
                source_allowed(role, record.source_router.as_deref())
                    .then(|| self.open(id, &record))
                    .transpose()
            });
            match visible {
                Ok(Some(preset)) => presets.push(preset.redacted()),
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(file = name, %error, "preset record skipped: unreadable");
                }
            }
        }
        presets.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(presets)
    }

    /// Gets one preset, revealing command secrets only with `RevealSecrets`.
    ///
    /// # Errors
    ///
    /// Returns permission, missing-record (also for a preset outside the caller's scope),
    /// decryption, malformed-record, or I/O errors.
    #[inline]
    pub fn get(&self, role: &Role, id: &str) -> Result<Preset, PresetError> {
        validate_id(id)?;
        require_permission(role, Permission::Read)?;
        let record = self.read_authorized(role, id)?;
        let preset = self.open(id, &record)?;
        Ok(if role.grants(Permission::RevealSecrets) {
            preset
        } else {
            preset.redacted()
        })
    }

    /// Opens one preset with its protected command values for the preset applier only.
    ///
    /// Requires `Migrate` on the persisted source scope. The returned preset carries secret
    /// values; callers pass it to [`super::apply::request`] and never display it.
    ///
    /// # Errors
    ///
    /// Returns permission, missing-record (also for a preset outside the caller's scope),
    /// decryption, malformed-record, or I/O errors.
    #[inline]
    pub fn load_for_apply(&self, role: &Role, id: &str) -> Result<Preset, PresetError> {
        validate_id(id)?;
        let record = self.read_authorized(role, id)?;
        self.open(id, &record)
    }

    /// Deletes one preset after checking its persisted source scope.
    ///
    /// # Errors
    ///
    /// Returns permission, missing-record (also for a preset outside the caller's scope),
    /// malformed-record, lock, or I/O errors.
    #[inline]
    pub fn delete(&self, role: &Role, id: &str) -> Result<(), PresetError> {
        validate_id(id)?;
        require_permission(role, Permission::Migrate)?;
        let _lock = self.state.lock("presets")?;
        let _authorized = self.read_authorized(role, id)?;
        fs::remove_file(self.path(id)).map_err(map_io)
    }

    /// Reads the record of `id` for a caller holding `Migrate` on its source router.
    ///
    /// A missing record and one outside the caller's scope both answer
    /// [`PresetError::NotFound`], after the same read, so the answer tells nothing about
    /// presets of other routers. So does an unparsable record, except to a caller whose
    /// scope covers every router.
    ///
    /// # Errors
    ///
    /// Returns [`PresetError::Forbidden`] without `Migrate` (before any read), then
    /// missing-record, malformed-record, or I/O errors.
    fn read_authorized(&self, role: &Role, id: &str) -> Result<PresetRecord, PresetError> {
        require_permission(role, Permission::Migrate)?;
        match read_record(self.path(id)) {
            Ok(record) => authorize_source(role, record.source_router.as_deref())
                .map(|()| record)
                .map_err(|_forbidden| PresetError::NotFound),
            Err(PresetError::Malformed) => Err(authorize_any_source(role)
                .map_or(PresetError::NotFound, |()| PresetError::Malformed)),
            Err(error) => Err(error),
        }
    }

    /// Authorizes replacing whatever is stored under `id`; the caller holds the lock.
    ///
    /// # Errors
    ///
    /// Returns [`PresetError::Forbidden`] for a preset outside the caller's scope, or for an
    /// unreadable record unless the caller's scope covers every router; I/O errors.
    fn authorize_replace(&self, role: &Role, id: &str) -> Result<(), PresetError> {
        let stored = match read_record(self.path(id)) {
            Err(PresetError::NotFound) => return Ok(()),
            Ok(record) => self
                .open(id, &record)
                .map(|preset| preset.source_router().map(str::to_owned)),
            Err(error) => Err(error),
        };
        match stored {
            Ok(router) => authorize_source(role, router.as_deref()),
            Err(PresetError::Malformed | PresetError::Crypto(_)) => authorize_any_source(role),
            Err(error) => Err(error),
        }
    }

    /// Encrypts and atomically replaces one preset record under the held `presets` lock.
    ///
    /// # Errors
    ///
    /// Returns serialization, encryption, or I/O errors.
    fn save(&self, preset: &Preset, _lock: &StateLock) -> Result<(), PresetError> {
        let directory = self.directory();
        create_private_dir(&directory)?;
        let plaintext = secret_json(&SealedPayload {
            id: &preset.id,
            name: &preset.name,
            description: &preset.description,
            groups: &preset.groups,
            source: &preset.source,
            lines: LineText::new(&preset.lines),
            created_by: &preset.created_by,
        })
        .map_err(|_error| PresetError::Malformed)?;
        let record = PresetRecord {
            schema: SCHEMA,
            source_router: preset.source_router().map(str::to_owned),
            sealed: self.key.seal(&Binding::preset(&preset.id), &plaintext)?,
        };
        let bytes = serde_json::to_vec(&record).map_err(|_error| PresetError::Malformed)?;
        write_atomic(&directory, &format!("{}.json", preset.id), &bytes)?;
        Ok(())
    }

    /// Decrypts and parses one record.
    ///
    /// # Errors
    ///
    /// Returns schema, decryption, or payload parsing errors.
    fn open(&self, id: &str, record: &PresetRecord) -> Result<Preset, PresetError> {
        if record.schema != SCHEMA {
            return Err(PresetError::Malformed);
        }
        let plaintext = self.key.open(&Binding::preset(id), &record.sealed)?;
        let payload: PresetPayload = serde_json::from_str(plaintext.expose_secret())
            .map_err(|_error| PresetError::Malformed)?;
        if payload.id != id || payload.source.router_id != record.source_router {
            return Err(PresetError::Malformed);
        }
        let lines = payload
            .lines
            .iter()
            .map(|line| parse_line(line).ok_or(PresetError::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Preset {
            id: payload.id,
            name: payload.name,
            description: payload.description,
            groups: payload.groups,
            source: payload.source,
            lines: Vec::new(),
            created_by: payload.created_by,
        }
        .with_lines(lines))
    }

    /// Returns the preset directory below application state.
    fn directory(&self) -> PathBuf {
        records_dir(&self.state)
    }

    /// Returns one preset record path.
    fn path(&self, id: &str) -> PathBuf {
        record_path(&self.state, id)
    }
}

/// The source router that the plaintext envelope of preset `id` in `state` names, read
/// without the master key and without an authorization check.
///
/// It is for authorization only: the caller checks a principal's permissions on the
/// answer before it acts for that principal, and never shows it.
/// [`PresetStore::load_for_apply`] checks the source scope again when it opens the preset.
///
/// # Errors
///
/// Returns invalid-id, missing-record, malformed-record, or I/O errors.
#[inline]
pub fn recorded_source(state: &StateStore, id: &str) -> Result<Option<String>, PresetError> {
    validate_id(id)?;
    read_record(record_path(state, id)).map(|record| record.source_router)
}

/// Returns the preset directory below the state directory `state`.
fn records_dir(state: &StateStore) -> PathBuf {
    state.dir().join("presets")
}

/// Returns the record path of preset `id` below the state directory `state`.
fn record_path(state: &StateStore, id: &str) -> PathBuf {
    records_dir(state).join(format!("{id}.json"))
}

/// Reads one encrypted preset envelope.
///
/// # Errors
///
/// Returns missing-file, I/O, or malformed-record errors.
fn read_record(path: PathBuf) -> Result<PresetRecord, PresetError> {
    let bytes = fs::read(path).map_err(map_io)?;
    serde_json::from_slice(&bytes).map_err(|_error| PresetError::Malformed)
}

/// Maps missing records separately from other preset I/O errors.
fn map_io(error: io::Error) -> PresetError {
    if error.kind() == io::ErrorKind::NotFound {
        PresetError::NotFound
    } else {
        PresetError::Io(error)
    }
}
