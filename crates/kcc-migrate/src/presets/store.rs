//! Encrypted preset capture and persistence.

use std::{fs, io, path::PathBuf};

use kcc_app::{
    permissions::{Permission, Role},
    persist::{StateError, StateStore},
    registry::{RegistryError, authorize},
    secrets::{CryptoError, MasterKey, SealedSecret},
};
use kcc_config::config_text::Ast;
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    groups::{GroupError, SettingsGroupEngine},
    model::{CaptureRequest, Preset, PresetSource, parse_line},
};

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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
/// Complete payload protected by the master key.
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
    lines: Vec<String>,
    /// Creator identity.
    created_by: String,
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
    /// # Errors
    ///
    /// Returns authorization, group-selection, validation, encryption, or I/O errors.
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
        self.save(&preset)?;
        Ok(preset.redacted())
    }

    /// Lists metadata-visible presets whose router source is in the caller's scope.
    ///
    /// # Errors
    ///
    /// Returns permission, decryption, malformed-record, or I/O errors.
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
            let Some(id) = file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            let record = read_record(entry.path())?;
            if source_allowed(role, record.source_router.as_deref()) {
                presets.push(self.open(id, &record)?.redacted());
            }
        }
        presets.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(presets)
    }

    /// Gets one preset, revealing command secrets only with `RevealSecrets`.
    ///
    /// # Errors
    ///
    /// Returns permission, missing-record, decryption, malformed-record, or I/O errors.
    #[inline]
    pub fn get(&self, role: &Role, id: &str) -> Result<Preset, PresetError> {
        validate_id(id)?;
        require_permission(role, Permission::Read)?;
        let record = read_record(self.path(id))?;
        authorize_source(role, record.source_router.as_deref())?;
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
    /// Returns permission, missing-record, decryption, malformed-record, or I/O errors.
    #[inline]
    pub fn load_for_apply(&self, role: &Role, id: &str) -> Result<Preset, PresetError> {
        validate_id(id)?;
        let record = read_record(self.path(id))?;
        authorize_source(role, record.source_router.as_deref())?;
        self.open(id, &record)
    }

    /// Deletes one preset after checking its persisted source scope.
    ///
    /// # Errors
    ///
    /// Returns permission, missing-record, malformed-record, lock, or I/O errors.
    #[inline]
    pub fn delete(&self, role: &Role, id: &str) -> Result<(), PresetError> {
        validate_id(id)?;
        require_permission(role, Permission::Migrate)?;
        let record = read_record(self.path(id))?;
        authorize_source(role, record.source_router.as_deref())?;
        let _lock = self.state.lock("presets")?;
        fs::remove_file(self.path(id)).map_err(map_io)
    }

    /// Gets one preset with its command secrets to plan and apply it, never to show it.
    ///
    /// Needs `Migrate` and the preset's source scope, like [`delete`](Self::delete); the
    /// secrets travel only to the target router through the protected applier.
    ///
    /// # Errors
    ///
    /// Returns permission, missing-record, decryption, malformed-record, or I/O errors.
    #[inline]
    pub fn get_for_apply(&self, role: &Role, id: &str) -> Result<Preset, PresetError> {
        validate_id(id)?;
        let record = read_record(self.path(id))?;
        authorize_source(role, record.source_router.as_deref())?;
        self.open(id, &record)
    }

    /// Encrypts and atomically replaces one preset record.
    ///
    /// # Errors
    ///
    /// Returns serialization, encryption, locking, or I/O errors.
    fn save(&self, preset: &Preset) -> Result<(), PresetError> {
        let directory = self.directory();
        fs::create_dir_all(&directory).map_err(PresetError::Io)?;
        let payload = PresetPayload {
            id: preset.id.clone(),
            name: preset.name.clone(),
            description: preset.description.clone(),
            groups: preset.groups.clone(),
            source: preset.source.clone(),
            lines: preset.command_text(),
            created_by: preset.created_by.clone(),
        };
        let plaintext = SecretString::from(
            serde_json::to_string(&payload).map_err(|_error| PresetError::Malformed)?,
        );
        let record = PresetRecord {
            schema: SCHEMA,
            source_router: preset.source_router().map(str::to_owned),
            sealed: self.key.seal(&owner(&preset.id), &plaintext)?,
        };
        let bytes = serde_json::to_vec(&record).map_err(|_error| PresetError::Malformed)?;
        let _lock = self.state.lock("presets")?;
        let temporary = directory.join(format!(".{}.tmp", preset.id));
        fs::write(&temporary, bytes).map_err(PresetError::Io)?;
        fs::rename(&temporary, self.path(&preset.id)).map_err(PresetError::Io)
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
        let plaintext = self.key.open(&owner(id), &record.sealed)?;
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
        self.state.dir().join("presets")
    }

    /// Returns one preset record path.
    fn path(&self, id: &str) -> PathBuf {
        self.directory().join(format!("{id}.json"))
    }
}

/// Validates a file-safe preset id.
///
/// # Errors
///
/// Returns [`PresetError::InvalidId`] for an empty, oversized, or unsafe id.
fn validate_id(id: &str) -> Result<(), PresetError> {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    valid.then_some(()).ok_or(PresetError::InvalidId)
}

/// Requires an application permission without consulting a router scope.
///
/// # Errors
///
/// Returns [`PresetError::Forbidden`] when the role lacks the permission.
fn require_permission(role: &Role, permission: Permission) -> Result<(), PresetError> {
    role.grants(permission)
        .then_some(())
        .ok_or(PresetError::Forbidden)
}

/// Authorizes migration access to an optional registered source router.
///
/// # Errors
///
/// Returns [`PresetError::Forbidden`] when permission or source scope is absent.
fn authorize_source(role: &Role, source_router: Option<&str>) -> Result<(), PresetError> {
    require_permission(role, Permission::Migrate)?;
    source_router.map_or(Ok(()), |router_id| {
        authorize(role, Permission::Migrate, router_id).map_err(map_registry)
    })
}

/// Reports whether list output may expose a preset from the source router.
fn source_allowed(role: &Role, source_router: Option<&str>) -> bool {
    role.grants(Permission::Read)
        && source_router
            .is_none_or(|router_id| authorize(role, Permission::Read, router_id).is_ok())
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

/// Builds associated data binding ciphertext to one preset id.
fn owner(id: &str) -> String {
    format!("preset:{id}")
}

/// Hides registry authorization detail behind the preset boundary.
fn map_registry(_error: RegistryError) -> PresetError {
    PresetError::Forbidden
}

/// Maps missing records separately from other preset I/O errors.
fn map_io(error: io::Error) -> PresetError {
    if error.kind() == io::ErrorKind::NotFound {
        PresetError::NotFound
    } else {
        PresetError::Io(error)
    }
}
