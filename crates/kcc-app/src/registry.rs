//! Router profile registry and shared authenticated client pool.
#![expect(
    clippy::absolute_paths,
    clippy::chunks_exact_to_as_chunks,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::missing_inline_in_public_items,
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::significant_drop_tightening,
    clippy::string_slice,
    clippy::unnested_or_patterns,
    clippy::renamed_function_params,
    reason = "the plan mandates registry names and validated fixed-width parsing; async registry methods are not inline candidates"
)]

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, str::FromStr as _};
use std::{fs, io, path::PathBuf};

use kcc_rci::{
    AllowedNetwork, OutboundPolicy, RciClient, RciClientOptions, RciError, RouterUrl, TlsMode,
    auth::Credentials,
    capabilities::RouterInfo,
    session::{HttpTimeouts, SessionManager},
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;

use crate::{
    permissions::{Permission, Role},
    persist::{Migration, StateDoc, StateError, StateStore},
    settings::{OutboundConfig, RouterAuth, RouterProfile, RouterTls},
};

/// A state-backed router profile with optional read-only polling credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ManagedRouterProfile {
    /// Stable slug id (`[a-z0-9-]{1,32}`).
    pub id: String,
    /// Router base URL.
    pub url: Url,
    /// Primary management login.
    pub login: String,
    /// File holding the primary password.
    pub password_file: PathBuf,
    /// Optional read-only polling login.
    pub read_login: Option<String>,
    /// Optional file holding the read-only polling password.
    pub read_password_file: Option<PathBuf>,
    /// TLS policy.
    pub tls: RouterTls,
    /// Whether live tests may use this router.
    pub test_device: bool,
    /// Free-form labels.
    pub tags: Vec<String>,
}

impl ManagedRouterProfile {
    /// Creates a password-authenticated profile with optional fields unset.
    #[inline]
    #[must_use]
    pub fn new(id: String, url: Url, login: String, password_file: PathBuf) -> Self {
        Self {
            id,
            url,
            login,
            password_file,
            read_login: None,
            read_password_file: None,
            tls: RouterTls::Verify,
            test_device: false,
            tags: Vec::new(),
        }
    }

    /// Validates the profile at the registry boundary.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::InvalidProfile`] for invalid ids, URLs, or credential pairs.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if !valid_router_id(&self.id) {
            return Err(RegistryError::InvalidProfile {
                reason: "id must match [a-z0-9-]{1,32}".to_owned(),
            });
        }
        if !matches!(self.url.scheme(), "http" | "https")
            || self.url.host().is_none()
            || self.url.path() != "/"
            || self.url.query().is_some()
            || self.url.fragment().is_some()
        {
            return Err(RegistryError::InvalidProfile {
                reason: "url must be an http(s) origin".to_owned(),
            });
        }
        if self.login.is_empty() {
            return Err(RegistryError::InvalidProfile {
                reason: "login must not be empty".to_owned(),
            });
        }
        match (&self.read_login, &self.read_password_file) {
            (None, None) => Ok(()),
            (Some(login), Some(_)) if !login.is_empty() => Ok(()),
            (Some(_), Some(_)) | (Some(_), None) | (None, Some(_)) => {
                Err(RegistryError::InvalidProfile {
                    reason: "read_login and read_password_file must be set together".to_owned(),
                })
            }
        }
    }
}

/// Persisted state-defined router profiles.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RoutersDocument {
    /// State-defined profiles.
    pub routers: Vec<ManagedRouterProfile>,
}

impl StateDoc for RoutersDocument {
    const FILE_NAME: &'static str = "routers.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// Where a merged profile was defined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProfileSource {
    /// Read-only `kcc.toml` profile.
    Config,
    /// Mutable state profile.
    State,
}

/// One merged registry entry.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct RegistryEntry {
    /// Profile data.
    pub profile: ManagedRouterProfile,
    /// Definition source.
    pub source: ProfileSource,
}

/// Registry failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// The caller lacks the required permission or router scope.
    #[error("permission denied for router {router}")]
    PermissionDenied {
        /// Router id.
        router: String,
    },
    /// A profile is malformed.
    #[error("invalid router profile: {reason}")]
    InvalidProfile {
        /// Validation reason.
        reason: String,
    },
    /// A profile id is already occupied.
    #[error("router profile {id} already exists")]
    AlreadyExists {
        /// Profile id.
        id: String,
    },
    /// A profile does not exist.
    #[error("router profile {id} was not found")]
    NotFound {
        /// Profile id.
        id: String,
    },
    /// Config-defined profiles are immutable through the registry.
    #[error("router profile {id} is config-defined and read-only")]
    ConfigDefined {
        /// Profile id.
        id: String,
    },
    /// A credential file could not be read.
    #[error("cannot read router credential file {path}: {source}")]
    CredentialFile {
        /// Credential path.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// RCI connection or authentication failed.
    #[error(transparent)]
    Rci(#[from] RciError),
}

/// Merged router registry and lazy one-client-per-profile pool.
pub struct RouterRegistry {
    /// State store.
    store: StateStore,
    /// Immutable config-defined profiles.
    config: BTreeMap<String, ManagedRouterProfile>,
    /// Outbound destination policy.
    outbound: OutboundPolicy,
    /// Lazy shared clients.
    clients: Mutex<BTreeMap<String, Arc<RciClient>>>,
}

impl fmt::Debug for RouterRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouterRegistry")
            .field("store", &self.store)
            .field("config_ids", &self.config.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl RouterRegistry {
    /// Builds a registry from immutable config profiles and mutable state profiles.
    ///
    /// # Errors
    ///
    /// Returns a profile or outbound-policy validation error.
    pub fn new(
        store: StateStore,
        config_profiles: &[RouterProfile],
        outbound: &OutboundConfig,
    ) -> Result<Self, RegistryError> {
        let mut config = BTreeMap::new();
        for profile in config_profiles {
            let converted = convert_config_profile(profile)?;
            converted.validate()?;
            if config.insert(converted.id.clone(), converted).is_some() {
                return Err(RegistryError::AlreadyExists {
                    id: profile.name.clone(),
                });
            }
        }
        let networks = outbound
            .allowed_networks
            .iter()
            .map(|network| AllowedNetwork::new(network.addr(), network.prefix_len()))
            .collect::<Result<Vec<_>, _>>()?;
        let policy = OutboundPolicy::default()
            .with_allowed_networks(networks)
            .with_allowed_suffixes(outbound.allowed_suffixes.clone())
            .with_loopback(outbound.allow_loopback);
        Ok(Self {
            store,
            config,
            outbound: policy,
            clients: Mutex::new(BTreeMap::new()),
        })
    }

    /// Lists merged profiles, with config definitions taking precedence on id collisions.
    ///
    /// # Errors
    ///
    /// Returns state errors when `routers.json` is unreadable.
    pub fn list(&self) -> Result<Vec<RegistryEntry>, RegistryError> {
        let mut merged = self
            .state_profiles()?
            .into_iter()
            .map(|profile| {
                (
                    profile.id.clone(),
                    RegistryEntry {
                        profile,
                        source: ProfileSource::State,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        for profile in self.config.values() {
            drop(merged.insert(
                profile.id.clone(),
                RegistryEntry {
                    profile: profile.clone(),
                    source: ProfileSource::Config,
                },
            ));
        }
        Ok(merged.into_values().collect())
    }

    /// Gets a merged profile.
    ///
    /// # Errors
    ///
    /// Returns state errors or [`RegistryError::NotFound`].
    pub fn get(&self, id: &str) -> Result<RegistryEntry, RegistryError> {
        self.list()?
            .into_iter()
            .find(|entry| entry.profile.id == id)
            .ok_or_else(|| RegistryError::NotFound { id: id.to_owned() })
    }

    /// Creates a mutable state profile.
    ///
    /// # Errors
    ///
    /// Returns permission, validation, duplicate, or state errors.
    pub async fn create(
        &self,
        role: &Role,
        profile: ManagedRouterProfile,
    ) -> Result<(), RegistryError> {
        authorize(role, Permission::ManageRouters, &profile.id)?;
        profile.validate()?;
        if self.config.contains_key(&profile.id) {
            return Err(RegistryError::AlreadyExists { id: profile.id });
        }
        let id = profile.id.clone();
        let inserted = self.store.update::<RoutersDocument, _, _>(|document| {
            if document.routers.iter().any(|entry| entry.id == id) {
                false
            } else {
                document.routers.push(profile);
                true
            }
        })?;
        if !inserted {
            return Err(RegistryError::AlreadyExists { id });
        }
        drop(self.clients.lock().await.remove(&id));
        Ok(())
    }

    /// Replaces a mutable state profile.
    ///
    /// # Errors
    ///
    /// Returns permission, validation, config-defined, missing, or state errors.
    pub async fn update(
        &self,
        role: &Role,
        profile: ManagedRouterProfile,
    ) -> Result<(), RegistryError> {
        authorize(role, Permission::ManageRouters, &profile.id)?;
        profile.validate()?;
        if self.config.contains_key(&profile.id) {
            return Err(RegistryError::ConfigDefined { id: profile.id });
        }
        let id = profile.id.clone();
        let replaced = self.store.update::<RoutersDocument, _, _>(|document| {
            match document.routers.iter_mut().find(|entry| entry.id == id) {
                Some(entry) => {
                    *entry = profile;
                    true
                }
                None => false,
            }
        })?;
        if !replaced {
            return Err(RegistryError::NotFound { id });
        }
        drop(self.clients.lock().await.remove(&id));
        Ok(())
    }

    /// Deletes a mutable state profile.
    ///
    /// # Errors
    ///
    /// Returns permission, config-defined, missing, or state errors.
    pub async fn delete(&self, role: &Role, id: &str) -> Result<(), RegistryError> {
        authorize(role, Permission::ManageRouters, id)?;
        if self.config.contains_key(id) {
            return Err(RegistryError::ConfigDefined { id: id.to_owned() });
        }
        let removed = self.store.update::<RoutersDocument, _, _>(|document| {
            let before = document.routers.len();
            document.routers.retain(|entry| entry.id != id);
            document.routers.len() != before
        })?;
        if !removed {
            return Err(RegistryError::NotFound { id: id.to_owned() });
        }
        drop(self.clients.lock().await.remove(id));
        Ok(())
    }

    /// Returns the one lazily constructed shared client for a profile.
    ///
    /// # Errors
    ///
    /// Returns profile, credential, policy, or transport errors.
    // NOT cancel-safe: cancellation may abandon DNS resolution, but sends no mutation.
    pub async fn client(&self, id: &str) -> Result<Arc<RciClient>, RegistryError> {
        let mut clients = self.clients.lock().await;
        if let Some(client) = clients.get(id) {
            return Ok(Arc::clone(client));
        }
        let profile = self.get(id)?.profile;
        let client = Arc::new(
            self.connect_client(&profile, CredentialUse::Primary)
                .await?,
        );
        drop(clients.insert(id.to_owned(), Arc::clone(&client)));
        Ok(client)
    }

    /// Builds an independent read-only client when configured, otherwise returns the shared client.
    ///
    /// # Errors
    ///
    /// Returns profile, credential, policy, or transport errors.
    // NOT cancel-safe: cancellation may abandon DNS resolution, but sends no mutation.
    pub async fn poll_client(&self, id: &str) -> Result<Arc<RciClient>, RegistryError> {
        let profile = self.get(id)?.profile;
        if profile.read_login.is_some() {
            return Ok(Arc::new(
                self.connect_client(&profile, CredentialUse::ReadOnly)
                    .await?,
            ));
        }
        self.client(id).await
    }

    /// Authenticates and detects one profile without adding it to the registry.
    ///
    /// # Errors
    ///
    /// Returns profile, credential, authentication, detection, or policy errors.
    // cancel-safe: every router operation is a read.
    pub async fn test_connection(
        &self,
        profile: &ManagedRouterProfile,
    ) -> Result<RouterInfo, RegistryError> {
        profile.validate()?;
        let router = router_url(profile)?;
        let credentials = credentials(profile, CredentialUse::Primary)?;
        let tls = tls_mode(&profile.tls)?;
        let builder = self
            .outbound
            .client_builder(&router, &tls, HttpTimeouts::default())
            .await?;
        let session = SessionManager::with_client_builder(
            router.clone(),
            credentials,
            HttpTimeouts::default(),
            builder,
        )?;
        session.ensure_session().await?;
        RouterInfo::detect(&session, &router)
            .await
            .map_err(RegistryError::from)
    }

    /// Detects a registered router using its read-only credentials when available.
    ///
    /// # Errors
    ///
    /// Returns profile, credential, authentication, detection, or policy errors.
    // cancel-safe: every router operation is a read.
    pub async fn poll_info(&self, id: &str) -> Result<RouterInfo, RegistryError> {
        let profile = self.get(id)?.profile;
        profile.validate()?;
        let selected = if profile.read_login.is_some() {
            CredentialUse::ReadOnly
        } else {
            CredentialUse::Primary
        };
        let router = router_url(&profile)?;
        let tls = tls_mode(&profile.tls)?;
        let builder = self
            .outbound
            .client_builder(&router, &tls, HttpTimeouts::default())
            .await?;
        let session = SessionManager::with_client_builder(
            router.clone(),
            credentials(&profile, selected)?,
            HttpTimeouts::default(),
            builder,
        )?;
        session.ensure_session().await?;
        RouterInfo::detect(&session, &router)
            .await
            .map_err(RegistryError::from)
    }

    /// Loads state profiles and rejects malformed persisted data.
    fn state_profiles(&self) -> Result<Vec<ManagedRouterProfile>, RegistryError> {
        let document = self.store.read::<RoutersDocument>()?.unwrap_or_default();
        for profile in &document.routers {
            profile.validate()?;
        }
        Ok(document.routers)
    }

    /// Connects one client with the selected credential pair.
    async fn connect_client(
        &self,
        profile: &ManagedRouterProfile,
        credential_use: CredentialUse,
    ) -> Result<RciClient, RegistryError> {
        let mut options = RciClientOptions::default();
        options.outbound = self.outbound.clone();
        options.tls = tls_mode(&profile.tls)?;
        RciClient::connect_with(
            router_url(profile)?,
            credentials(profile, credential_use)?,
            options,
        )
        .await
        .map_err(RegistryError::from)
    }
}

/// Credential pair selected for a client.
#[derive(Clone, Copy)]
enum CredentialUse {
    /// Primary management credentials.
    Primary,
    /// Optional read-only polling credentials.
    ReadOnly,
}

/// Converts a config-defined profile into the common registry representation.
fn convert_config_profile(profile: &RouterProfile) -> Result<ManagedRouterProfile, RegistryError> {
    if profile.auth == RouterAuth::Token || profile.token_file.is_some() {
        return Err(RegistryError::InvalidProfile {
            reason: "token profiles are not supported by the current RciClient API".to_owned(),
        });
    }
    Ok(ManagedRouterProfile {
        id: profile.name.clone(),
        url: profile.url.clone(),
        login: profile.login.clone().unwrap_or_default(),
        password_file: profile.password_file.clone().ok_or_else(|| {
            RegistryError::InvalidProfile {
                reason: "password_file is required".to_owned(),
            }
        })?,
        read_login: profile.read_login.clone(),
        read_password_file: profile.read_password_file.clone(),
        tls: profile.tls.clone(),
        test_device: profile.test_device,
        tags: profile.tags.clone(),
    })
}

/// Reads the selected credentials.
fn credentials(
    profile: &ManagedRouterProfile,
    credential_use: CredentialUse,
) -> Result<Credentials, RegistryError> {
    let (login, path) = match credential_use {
        CredentialUse::Primary => (profile.login.as_str(), &profile.password_file),
        CredentialUse::ReadOnly => (
            profile
                .read_login
                .as_deref()
                .ok_or_else(|| RegistryError::InvalidProfile {
                    reason: "read_login is missing".to_owned(),
                })?,
            profile
                .read_password_file
                .as_ref()
                .ok_or_else(|| RegistryError::InvalidProfile {
                    reason: "read_password_file is missing".to_owned(),
                })?,
        ),
    };
    let password = fs::read_to_string(path).map_err(|source| RegistryError::CredentialFile {
        path: path.clone(),
        source,
    })?;
    Ok(Credentials::new(
        login.to_owned(),
        SecretString::from(password.trim_end_matches(['\r', '\n']).to_owned()),
    ))
}

/// Converts a profile URL into the protocol origin type.
fn router_url(profile: &ManagedRouterProfile) -> Result<RouterUrl, RegistryError> {
    RouterUrl::from_str(profile.url.as_str()).map_err(|_error| RegistryError::InvalidProfile {
        reason: "url is not a valid router origin".to_owned(),
    })
}

/// Converts the settings TLS shape into the RCI TLS policy.
fn tls_mode(tls: &RouterTls) -> Result<TlsMode, RegistryError> {
    match tls {
        RouterTls::Verify => Ok(TlsMode::Verify),
        RouterTls::PinSha256(encoded) => {
            let mut bytes = [0_u8; 32];
            if encoded.len() != 64 {
                return Err(RegistryError::InvalidProfile {
                    reason: "TLS pin must be 64 hex digits".to_owned(),
                });
            }
            for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
                let pair_text =
                    core::str::from_utf8(pair).map_err(|_error| RegistryError::InvalidProfile {
                        reason: "TLS pin must be hexadecimal".to_owned(),
                    })?;
                bytes[index] = u8::from_str_radix(pair_text, 16).map_err(|_error| {
                    RegistryError::InvalidProfile {
                        reason: "TLS pin must be hexadecimal".to_owned(),
                    }
                })?;
            }
            Ok(TlsMode::PinSha256(bytes))
        }
    }
}

/// Enforces an application permission and router scope.
pub(crate) fn authorize(
    role: &Role,
    permission: Permission,
    router: &str,
) -> Result<(), RegistryError> {
    if !role.grants(permission) || !scope_matches(&role.router_scope, router) {
        return Err(RegistryError::PermissionDenied {
            router: router.to_owned(),
        });
    }
    Ok(())
}

/// Matches the kit-compatible `*` glob semantics used by router scopes.
pub(crate) fn scope_matches(patterns: &[String], value: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| glob_matches(pattern, value))
}

/// Matches one `*`-only glob.
fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let pieces = pattern.split('*').collect::<Vec<_>>();
    if pieces.len() == 1 {
        return pattern == value;
    }
    let mut remainder = value;
    for (index, piece) in pieces.iter().enumerate() {
        if piece.is_empty() {
            continue;
        }
        if index == 0 && !pattern.starts_with('*') {
            let Some(rest) = remainder.strip_prefix(piece) else {
                return false;
            };
            remainder = rest;
        } else if index == pieces.len().saturating_sub(1) && !pattern.ends_with('*') {
            return remainder.ends_with(piece);
        } else if let Some(position) = remainder.find(piece) {
            remainder = &remainder[position.saturating_add(piece.len())..];
        } else {
            return false;
        }
    }
    true
}

/// Slug validation for router ids.
fn valid_router_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
