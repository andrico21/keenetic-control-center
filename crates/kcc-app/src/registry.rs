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

mod auth;
mod budgets;
pub mod sealed_edit;
mod stored;
#[cfg(test)]
mod transition_tests;

use alloc::{collections::BTreeMap, sync::Arc};
use core::{fmt, str::FromStr as _};
use std::{
    io,
    path::{Path, PathBuf},
    sync::{PoisonError, RwLock},
};

use kcc_rci::{
    AllowedNetwork, OutboundPolicy, RciClient, RciClientOptions, RciError, RouterUrl, TlsMode,
    auth::Credentials, auth_options::Options as RciAuthOptions, capabilities::RouterInfo,
    observe::RciObserver,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{Mutex, OnceCell, watch},
    task::spawn_blocking,
};
use url::Url;

use crate::{
    credentials::{CredentialError, CredentialKind, CredentialStore},
    permissions::{Permission, Role},
    persist::{Migration, StateDoc, StateError, StateStore},
    settings::{Config, OutboundConfig, RouterAuth, RouterProfile, RouterTls, is_valid_router_id},
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
    /// Primary management login; may be empty for a token profile.
    pub login: String,
    /// File holding the primary password; unset for a token profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_file: Option<PathBuf>,
    /// Authentication scheme.
    #[serde(default, skip_serializing_if = "RouterAuth::is_auto")]
    pub auth: RouterAuth,
    /// File holding the API token, with `auth = Token` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
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
            password_file: Some(password_file),
            auth: RouterAuth::Auto,
            token_file: None,
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
    /// Returns [`RegistryError::InvalidProfile`] for invalid ids, URLs, credential sources,
    /// or credential pairs.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if !is_valid_router_id(&self.id) {
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
        auth::validate(self)?;
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

    /// The file holding this profile's credential of `kind`, when it has one.
    #[must_use]
    pub fn credential_path(&self, kind: CredentialKind) -> Option<&Path> {
        match kind {
            CredentialKind::Password => self.password_file.as_deref(),
            CredentialKind::Token => self.token_file.as_deref(),
            CredentialKind::ReadPassword => self.read_password_file.as_deref(),
        }
    }

    /// Whether this profile reaches a different endpoint than `before`: another URL,
    /// login or TLS pin. Such a change needs the primary credential again and drops the
    /// read-only credential unless it is given again.
    #[must_use]
    pub fn moves_endpoint(&self, before: &Self) -> bool {
        self.url != before.url || self.login != before.login || self.tls != before.tls
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
    /// Group or others can read a router credential file (unix only).
    #[error("router credential file {path} can be read by other users (chmod 600)")]
    CredentialPermissions {
        /// Credential path.
        path: PathBuf,
    },
    /// A kcc-managed encrypted credential could not be opened.
    #[error(transparent)]
    Credential(#[from] CredentialError),
    /// RCI connection or authentication failed.
    #[error(transparent)]
    Rci(#[from] RciError),
    /// The in-memory profile set is unavailable after a task panicked while updating it.
    #[error("router profile registry lock is poisoned")]
    ProfileLock,
    /// The task reading a router's credentials ended without an answer.
    #[error("router credential read did not complete")]
    CredentialRead,
}

/// Merged router registry and lazy one-client-per-profile pool.
pub struct RouterRegistry {
    /// State store.
    store: StateStore,
    /// Reloadable config-defined profiles.
    config: RwLock<BTreeMap<String, ManagedRouterProfile>>,
    /// Effective profiles observed at the last local mutation or reload.
    profiles: RwLock<BTreeMap<String, ManagedRouterProfile>>,
    /// Outbound destination policy.
    outbound: OutboundPolicy,
    /// Lazy shared clients, one slot per router id; a slot is built outside the map lock.
    clients: Mutex<BTreeMap<String, ClientSlot>>,
    /// Router budgets retained across client cache invalidation.
    budgets: budgets::Budgets,
    /// Per-router request and login observers (self-metrics).
    observers: Option<RciObserverFactory>,
    /// Encrypted credentials managed below the state root.
    credentials: Option<Arc<CredentialStore>>,
    /// Generation counter bumped after every change of the profile set.
    changes: watch::Sender<u64>,
}

/// The lazily built shared client of one router id.
type ClientSlot = Arc<OnceCell<Arc<RciClient>>>;

/// Builds the request and login observer of one router id (self-metrics).
pub type RciObserverFactory = Arc<dyn Fn(&str) -> Arc<dyn RciObserver> + Send + Sync>;

impl fmt::Debug for RouterRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let config_ids = self.config.read().map_or_else(
            |_error| Vec::new(),
            |config| config.keys().cloned().collect(),
        );
        formatter
            .debug_struct("RouterRegistry")
            .field("store", &self.store)
            .field("config_ids", &config_ids)
            .finish_non_exhaustive()
    }
}

impl RouterRegistry {
    /// Opens an opt-in factory-setup client without changing the registered profile.
    ///
    /// # Errors
    /// Returns permission, profile, credential, or connection errors.
    // cancel-safe: opens a client without writing router or registry state.
    pub async fn bootstrap_client(
        &self,
        role: &Role,
        id: &str,
    ) -> Result<Arc<RciClient>, RegistryError> {
        authorize(role, Permission::Migrate, id)?;
        let profile = self.get(id)?.profile;
        let mut options = RciClientOptions::default();
        options.outbound = self.outbound.clone();
        options.tls = tls_mode(&profile.tls)?;
        options.budget = Some(self.budgets.get(id).await);
        options.auth = auth::options(
            self.credentials.as_deref(),
            &profile,
            CredentialUse::Primary,
        )?;
        Ok(Arc::new(
            RciClient::connect_bootstrap_with(
                router_url(&profile)?,
                self.credentials(&profile, CredentialUse::Primary)?,
                options,
            )
            .await?,
        ))
    }

    /// Publishes a freshly authenticated client and replaces its primary password atomically.
    /// Only a leased workflow may call this transition.
    ///
    /// A Web UI or CLI profile gets the new password sealed and points at its sealed
    /// record; a `kcc.toml` profile (or any profile without a credential store) gets its
    /// own `password_file` rewritten. A token profile stores no password and keeps no
    /// cached client, so its next client signs in with the stored token.
    // NOT cancel-safe: once persistence begins, the transition runs without await points.
    pub(crate) async fn transition(
        &self,
        id: &str,
        client: Arc<RciClient>,
        replacement: Option<&Credentials>,
    ) -> Result<(), RegistryError> {
        let endpoint =
            Url::parse(client.router_url().as_str()).map_err(|_error| RciError::Validation)?;
        let mut clients = self.clients.lock().await;
        let source = if self.config.read().map_err(lock_error)?.contains_key(id) {
            ProfileSource::Config
        } else {
            ProfileSource::State
        };
        let mut profiles = self.profiles.write().map_err(lock_error)?;
        let mut profile = profiles
            .get(id)
            .cloned()
            .ok_or_else(|| RegistryError::NotFound { id: id.to_owned() })?;
        if let Some(credential) = replacement {
            stored::replace_password(
                self.credentials.as_deref(),
                source,
                &mut profile,
                credential,
            )?;
        }
        profile.url = endpoint;
        self.store.update::<RoutersDocument, _, _>(|document| {
            if let Some(stored) = document.routers.iter_mut().find(|entry| entry.id == id) {
                stored.clone_from(&profile);
            }
        })?;
        let token = profile.password_file.is_none();
        drop(profiles.insert(id.to_owned(), profile));
        if token {
            drop(clients.remove(id));
        } else {
            drop(clients.insert(id.to_owned(), Arc::new(OnceCell::from(client))));
        }
        Ok(())
    }

    /// Builds a registry from immutable config profiles and mutable state profiles.
    ///
    /// # Errors
    ///
    /// Returns a profile or outbound-policy validation error.
    pub fn new(
        store: StateStore,
        profiles: &[RouterProfile],
        outbound: &OutboundConfig,
    ) -> Result<Self, RegistryError> {
        let config = config_profiles(profiles)?;
        let state_profiles = read_state_profiles(&store)?;
        let effective = merged_profiles(&config, &state_profiles);
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
            config: RwLock::new(config),
            profiles: RwLock::new(effective),
            outbound: policy,
            clients: Mutex::new(BTreeMap::new()),
            budgets: budgets::Budgets::default(),
            observers: None,
            credentials: None,
            changes: watch::Sender::new(0),
        })
    }

    /// Attaches the encrypted credential store used by kcc-managed profiles.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Arc<CredentialStore>) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// The Web UI and CLI profiles whose password still sits in an external plaintext
    /// file instead of a sealed record, as `(router id, file)`.
    ///
    /// # Errors
    ///
    /// Returns registry lock or credential path errors.
    pub fn external_password_files(&self) -> Result<Vec<(String, PathBuf)>, RegistryError> {
        let mut external = Vec::new();
        for entry in self.list()? {
            if !matches!(entry.source, ProfileSource::State) {
                continue;
            }
            let Some(file) = entry.profile.password_file else {
                continue;
            };
            let managed = match &self.credentials {
                Some(store) => store.manages(&entry.profile.id, CredentialKind::Password, &file)?,
                None => false,
            };
            if !managed {
                external.push((entry.profile.id, file));
            }
        }
        Ok(external)
    }

    /// Follows changes of the profile set (create, update, delete, reload): the value is a
    /// generation counter bumped after each change, so a receiver re-reads
    /// [`RouterRegistry::list`] whenever it changes.
    #[must_use]
    pub fn subscribe_changes(&self) -> watch::Receiver<u64> {
        self.changes.subscribe()
    }

    /// Tells every change receiver that the profile set changed.
    fn changed(&self) {
        self.changes
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Attaches an observer to every client and detection session created from now on.
    #[must_use]
    pub fn with_rci_observers(mut self, factory: RciObserverFactory) -> Self {
        self.observers = Some(factory);
        self
    }

    /// The observer of router `id`, when a factory is attached.
    fn observer(&self, id: &str) -> Option<Arc<dyn RciObserver>> {
        self.observers.as_ref().map(|factory| factory(id))
    }

    /// Lists merged profiles, with config definitions taking precedence on id collisions.
    ///
    /// # Errors
    ///
    /// Returns state errors when `routers.json` is unreadable.
    pub fn list(&self) -> Result<Vec<RegistryEntry>, RegistryError> {
        let config = self.config.read().map_err(lock_error)?;
        let profiles = self.profiles.read().map_err(lock_error)?;
        Ok(profiles
            .values()
            .map(|profile| RegistryEntry {
                profile: profile.clone(),
                source: if config.contains_key(&profile.id) {
                    ProfileSource::Config
                } else {
                    ProfileSource::State
                },
            })
            .collect())
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
    // NOT cancel-safe: cancelled at the client-cache lock, the profile is already stored and loaded
    // but no stale client is evicted and no change notification is sent.
    pub async fn create(
        &self,
        role: &Role,
        profile: ManagedRouterProfile,
    ) -> Result<(), RegistryError> {
        authorize(role, Permission::ManageRouters, &profile.id)?;
        profile.validate()?;
        if self
            .config
            .read()
            .map_err(lock_error)?
            .contains_key(&profile.id)
        {
            return Err(RegistryError::AlreadyExists { id: profile.id });
        }
        let id = profile.id.clone();
        let loaded = profile.clone();
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
        drop(
            self.profiles
                .write()
                .map_err(lock_error)?
                .insert(id.clone(), loaded),
        );
        drop(self.clients.lock().await.remove(&id));
        self.changed();
        Ok(())
    }

    /// Replaces a mutable state profile.
    ///
    /// # Errors
    ///
    /// Returns permission, validation, config-defined, missing, or state errors.
    // NOT cancel-safe: cancelled at the client-cache lock, the new profile is stored and loaded
    // but the client built from the old one stays cached and no change notification is sent.
    pub async fn update(
        &self,
        role: &Role,
        profile: ManagedRouterProfile,
    ) -> Result<(), RegistryError> {
        authorize(role, Permission::ManageRouters, &profile.id)?;
        profile.validate()?;
        if self
            .config
            .read()
            .map_err(lock_error)?
            .contains_key(&profile.id)
        {
            return Err(RegistryError::ConfigDefined { id: profile.id });
        }
        let id = profile.id.clone();
        let loaded = profile.clone();
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
        drop(
            self.profiles
                .write()
                .map_err(lock_error)?
                .insert(id.clone(), loaded),
        );
        drop(self.clients.lock().await.remove(&id));
        self.changed();
        Ok(())
    }

    /// Deletes a mutable state profile.
    ///
    /// # Errors
    ///
    /// Returns permission, config-defined, missing, or state errors.
    // NOT cancel-safe: cancelled at the client-cache lock, the profile is already removed
    // but its cached client stays and no change notification is sent.
    pub async fn delete(&self, role: &Role, id: &str) -> Result<(), RegistryError> {
        authorize(role, Permission::ManageRouters, id)?;
        if self.config.read().map_err(lock_error)?.contains_key(id) {
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
        drop(self.profiles.write().map_err(lock_error)?.remove(id));
        drop(self.clients.lock().await.remove(id));
        self.changed();
        Ok(())
    }

    /// Returns the one lazily constructed shared client for a profile.
    ///
    /// The client is built in the router's own slot, outside the lock of the slot map, so
    /// a slow credential read or DNS lookup holds up only callers of the same router.
    ///
    /// # Errors
    ///
    /// Returns profile, credential, policy, or transport errors.
    // NOT cancel-safe: cancellation may abandon DNS resolution or a credential read, but
    // sends no mutation; the slot stays empty and the next caller builds the client.
    pub async fn client(&self, id: &str) -> Result<Arc<RciClient>, RegistryError> {
        drop(self.get(id)?);
        let slot = Arc::clone(self.clients.lock().await.entry(id.to_owned()).or_default());
        let client = slot
            .get_or_try_init(async || {
                let profile = self.get(id)?.profile;
                self.connect_client(&profile, CredentialUse::Primary)
                    .await
                    .map(Arc::new)
            })
            .await?;
        Ok(Arc::clone(client))
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
        let credentials = self.credentials(profile, CredentialUse::Primary)?;
        let options = auth::options(self.credentials.as_deref(), profile, CredentialUse::Primary)?;
        self.detect_with(profile, credentials, options).await
    }

    /// Authenticates with `secret` instead of the profile's credential file and detects
    /// the router without adding it to the registry, so a form can test credentials that
    /// are not stored yet. `secret` is the token when the profile's sign-in mode is
    /// `token`, otherwise the password; nothing is stored.
    ///
    /// # Errors
    ///
    /// Returns profile, authentication, detection, or policy errors.
    // cancel-safe: every router operation is a read.
    pub async fn test_connection_with(
        &self,
        profile: &ManagedRouterProfile,
        secret: SecretString,
    ) -> Result<RouterInfo, RegistryError> {
        profile.validate()?;
        let mut options = auth::mode_options(profile.auth);
        let credentials = if profile.auth == RouterAuth::Token {
            options.experimental_token = Some(secret);
            Credentials::new(profile.login.clone(), SecretString::from(String::new()))
        } else {
            Credentials::new(profile.login.clone(), secret)
        };
        self.detect_with(profile, credentials, options).await
    }

    /// The outbound policy every router connection passes, for checking a target before
    /// a profile is stored.
    #[must_use]
    pub const fn outbound_policy(&self) -> &OutboundPolicy {
        &self.outbound
    }

    /// Reloads config-defined and state-defined profiles, invalidating clients whose
    /// effective profile changed or disappeared.
    ///
    /// # Errors
    ///
    /// Returns profile validation, state storage, or registry lock errors.
    // NOT cancel-safe: cancelled at the client-cache lock, the new profiles are live while stale
    // cached clients remain and no change notification is sent.
    pub async fn reload(&self, config: &Config) -> Result<usize, RegistryError> {
        let replacement = config_profiles(&config.routers)?;
        let state_profiles = read_state_profiles(&self.store)?;
        let previous = self.profiles.read().map_err(lock_error)?.clone();
        let current = merged_profiles(&replacement, &state_profiles);
        let changed = previous
            .iter()
            .filter_map(|(id, profile)| (current.get(id) != Some(profile)).then_some(id.clone()))
            .chain(
                current
                    .keys()
                    .filter(|id| !previous.contains_key(*id))
                    .cloned(),
            )
            .collect::<Vec<_>>();
        *self.config.write().map_err(lock_error)? = replacement;
        *self.profiles.write().map_err(lock_error)? = current;
        let mut clients = self.clients.lock().await;
        for id in &changed {
            drop(clients.remove(id));
        }
        drop(clients);
        if !changed.is_empty() {
            self.changed();
        }
        Ok(changed.len())
    }

    /// Detects a registered router using its read-only credentials when available.
    ///
    /// # Errors
    ///
    /// Returns profile, credential, authentication, detection, or policy errors.
    // cancel-safe: every router operation is a read.
    pub async fn poll_info(&self, id: &str) -> Result<RouterInfo, RegistryError> {
        self.poll_client(id)
            .await?
            .detect()
            .await
            .map_err(RegistryError::from)
    }

    /// Opens a policy-checked session with `credentials` under the authentication policy
    /// `auth` and detects the router.
    // cancel-safe: every router operation is a read.
    async fn detect_with(
        &self,
        profile: &ManagedRouterProfile,
        credentials: Credentials,
        auth: RciAuthOptions,
    ) -> Result<RouterInfo, RegistryError> {
        let mut options = RciClientOptions::default();
        options.outbound = self.outbound.clone();
        options.tls = tls_mode(&profile.tls)?;
        options.budget = Some(self.budgets.get(&profile.id).await);
        options.auth = auth;
        RciClient::connect_with(router_url(profile)?, credentials, options)
            .await?
            .detect()
            .await
            .map_err(RegistryError::from)
    }

    /// Connects one client with the selected credential pair; the credential files and
    /// sealed records are read on the blocking pool.
    // NOT cancel-safe: cancellation may abandon DNS resolution or a credential read, but
    // sends no mutation.
    async fn connect_client(
        &self,
        profile: &ManagedRouterProfile,
        credential_use: CredentialUse,
    ) -> Result<RciClient, RegistryError> {
        let mut options = RciClientOptions::default();
        options.outbound = self.outbound.clone();
        options.tls = tls_mode(&profile.tls)?;
        options.observer = self.observer(&profile.id);
        options.budget = Some(self.budgets.get(&profile.id).await);
        let shared_store = self.credentials.clone();
        let owned = profile.clone();
        let (auth, credentials) = spawn_blocking(move || {
            let store = shared_store.as_deref();
            Ok::<_, RegistryError>((
                auth::options(store, &owned, credential_use)?,
                credentials(store, &owned, credential_use)?,
            ))
        })
        .await
        .map_err(|_join_error| RegistryError::CredentialRead)??;
        options.auth = auth;
        RciClient::connect_with(router_url(profile)?, credentials, options)
            .await
            .map_err(RegistryError::from)
    }

    /// Reads operator-managed files directly and opens kcc-managed sealed records.
    fn credentials(
        &self,
        profile: &ManagedRouterProfile,
        credential_use: CredentialUse,
    ) -> Result<Credentials, RegistryError> {
        credentials(self.credentials.as_deref(), profile, credential_use)
    }
}

/// Reads operator-managed files directly and opens kcc-managed sealed records.
fn credentials(
    store: Option<&CredentialStore>,
    profile: &ManagedRouterProfile,
    credential_use: CredentialUse,
) -> Result<Credentials, RegistryError> {
    if matches!(credential_use, CredentialUse::Primary) && profile.password_file.is_none() {
        return Ok(Credentials::new(
            profile.login.clone(),
            SecretString::from(String::new()),
        ));
    }
    let (login, path) = credential_parts(profile, credential_use)?;
    let kind = match credential_use {
        CredentialUse::Primary => CredentialKind::Password,
        CredentialUse::ReadOnly => CredentialKind::ReadPassword,
    };
    let secret = stored::secret(store, &profile.id, kind, path)?;
    Ok(Credentials::new(login.to_owned(), secret))
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
fn convert_config_profile(profile: &RouterProfile) -> ManagedRouterProfile {
    let auth = match (profile.auth, &profile.token_file) {
        (RouterAuth::Auto, Some(_)) => RouterAuth::Token,
        (auth, _) => auth,
    };
    ManagedRouterProfile {
        id: profile.name.clone(),
        url: profile.url.clone(),
        login: profile.login.clone().unwrap_or_default(),
        password_file: profile.password_file.clone(),
        auth,
        token_file: profile.token_file.clone(),
        read_login: profile.read_login.clone(),
        read_password_file: profile.read_password_file.clone(),
        tls: profile.tls.clone(),
        test_device: profile.test_device,
        tags: profile.tags.clone(),
    }
}

/// Converts and validates all config-defined profiles.
fn config_profiles(
    profiles: &[RouterProfile],
) -> Result<BTreeMap<String, ManagedRouterProfile>, RegistryError> {
    let mut converted = BTreeMap::new();
    for profile in profiles {
        let entry = convert_config_profile(profile);
        entry.validate()?;
        if converted.insert(entry.id.clone(), entry).is_some() {
            return Err(RegistryError::AlreadyExists {
                id: profile.name.clone(),
            });
        }
    }
    Ok(converted)
}

/// Produces the effective profile map with config definitions taking precedence.
fn merged_profiles(
    config: &BTreeMap<String, ManagedRouterProfile>,
    state: &[ManagedRouterProfile],
) -> BTreeMap<String, ManagedRouterProfile> {
    let mut merged = state
        .iter()
        .map(|profile| (profile.id.clone(), profile.clone()))
        .collect::<BTreeMap<_, _>>();
    for (id, profile) in config {
        drop(merged.insert(id.clone(), profile.clone()));
    }
    merged
}

/// Reads and validates mutable profiles from the state store.
fn read_state_profiles(store: &StateStore) -> Result<Vec<ManagedRouterProfile>, RegistryError> {
    let document = store.read::<RoutersDocument>()?.unwrap_or_default();
    for profile in &document.routers {
        profile.validate()?;
    }
    Ok(document.routers)
}

/// Converts a poisoned profile lock into the registry's stable error surface.
fn lock_error<T>(_error: PoisonError<T>) -> RegistryError {
    RegistryError::ProfileLock
}

/// Reads the selected credentials.
fn credential_parts(
    profile: &ManagedRouterProfile,
    credential_use: CredentialUse,
) -> Result<(&str, &PathBuf), RegistryError> {
    let (login, path) = match credential_use {
        CredentialUse::Primary => (
            profile.login.as_str(),
            profile
                .password_file
                .as_ref()
                .ok_or_else(|| RegistryError::InvalidProfile {
                    reason: "password_file is missing".to_owned(),
                })?,
        ),
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
    Ok((login, path))
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
pub fn authorize(role: &Role, permission: Permission, router: &str) -> Result<(), RegistryError> {
    if !role.grants(permission) || !scope_matches(&role.router_scope, router) {
        return Err(RegistryError::PermissionDenied {
            router: router.to_owned(),
        });
    }
    Ok(())
}

/// Matches the kit-compatible `*` glob semantics used by router scopes.
#[must_use]
pub fn scope_matches(patterns: &[String], value: &str) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| glob_matches(pattern, value))
}

/// Matches one `*`-only glob.
pub(crate) fn glob_matches(pattern: &str, value: &str) -> bool {
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
