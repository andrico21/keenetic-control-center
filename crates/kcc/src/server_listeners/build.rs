//! One listener generation's kit configuration, built and validated from the settings
//! before any running generation is touched.

extern crate alloc;

use alloc::sync::Arc;
use core::net::{IpAddr, SocketAddr};

use arc_swap::ArcSwap;
use kcc_app::{
    api_keys::api_key_entries,
    mcp_settings::ListenerKind,
    persist::StateStore,
    settings::{
        Config, ConfigError, McpConfig,
        mcp_schema::{DedicatedTls, Endpoint},
    },
};
use kcc_mcp::KccMcp;
use kcc_web::{
    WebState, admin::TransportReload, csp::security_headers, oauth::Activation, web_router,
};
use rmcp_server_kit::{
    RmcpServerKitError,
    auth::{AuthConfig, MtlsConfig, RateLimitConfig},
    oauth::OAuthConfig,
    rbac::RbacPolicy,
    transport::{McpServerConfig, ReadinessCheck, ReloadHandle, Validated},
};
use tokio::sync::oneshot;

use super::{
    health::Probe,
    sign_in::{client_certificates, external::ProviderRefusal, tokens},
    tls::leaf,
};
use crate::{
    server_mcp_auth::KccSignIn,
    server_metrics::{AttachError, Metrics},
    server_tls_dedicated::ensure,
    server_tls_key::readable,
};

/// What every generation is built from; owned by the supervisor for the whole process.
pub(crate) struct Shared {
    /// The validated configuration, environment overrides applied.
    pub(crate) config: Config,
    /// The state directory.
    pub(crate) state: StateStore,
    /// The `/readyz` probe.
    pub(crate) readiness: ReadinessCheck,
    /// The Web UI, served by the main listener; its sessions outlive every generation.
    pub(crate) web: Option<WebState>,
    /// The metrics exporter, served by the main listener only.
    pub(crate) metrics: Option<Metrics>,
    /// The handler every MCP session clones.
    pub(crate) live: Arc<ArcSwap<KccMcp>>,
    /// The key and role reload fan-out.
    pub(crate) reload: Arc<TransportReload>,
    /// kcc sign-in; `None` when kcc's authorization server has no issuer.
    pub(crate) sign_in: Option<Arc<KccSignIn>>,
}

/// Whether a build may run without the API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keys {
    /// Unreadable keys fail the build: nothing was stopped yet.
    Required,
    /// Unreadable keys start the generation with none (every key refused until the next
    /// reload): a previous generation must serve again after a failed restart.
    BestEffort,
}

/// The handler a generation's sessions clone.
#[derive(Clone)]
pub(crate) enum Factory {
    /// The live handler, reconfigured by live settings changes.
    Live(Arc<ArcSwap<KccMcp>>),
    /// A handler without tools (`endpoint = "dedicated"` on the main listener).
    Fixed(Arc<KccMcp>),
}

impl Factory {
    /// A handler for one new session.
    pub(crate) fn handler(&self) -> KccMcp {
        match self {
            Self::Live(live) => live.load().as_ref().clone(),
            Self::Fixed(handler) => handler.as_ref().clone(),
        }
    }
}

/// A validated generation, not yet bound.
pub(crate) struct Built {
    /// The listener.
    pub(crate) kind: ListenerKind,
    /// The settings it was built from, to build it again after a failed restart.
    pub(crate) settings: McpConfig,
    /// The kit configuration.
    pub(crate) config: Validated<McpServerConfig>,
    /// The address to bind.
    pub(crate) bind: SocketAddr,
    /// Its sessions' handler.
    pub(crate) factory: Factory,
    /// What its health check probes.
    pub(crate) probe: Probe,
    /// Receives its reload handle once it serves.
    pub(crate) handles: oneshot::Receiver<ReloadHandle>,
    /// What it accepts as a kcc sign-in listener; `None` without kcc sign-in.
    pub(crate) activation: Option<Activation>,
}

/// Why a generation could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "read beside `ServerError` and `ListenerError` as `BuildError`"
)]
pub enum BuildError {
    /// The kit refused the configuration.
    #[error("{0}")]
    Kit(#[from] RmcpServerKitError),
    /// The Web UI origins or the listen address are invalid.
    #[error("{0}")]
    Config(#[from] ConfigError),
    /// The metrics registry could not be set up.
    #[error("metrics: {0}")]
    Metrics(String),
    /// The API keys could not be read.
    #[error("API keys: {0}")]
    Keys(String),
    /// A TLS certificate or key could not be read or does not form a pair.
    #[error("TLS: {0}")]
    Tls(String),
    /// The TLS private key is readable by group or others.
    #[error("{}", readable(path))]
    TlsKeyReadable {
        /// The key file.
        path: std::path::PathBuf,
    },
    /// The dedicated listener has no TLS and binds a non-loopback address.
    #[error("a dedicated listener without TLS may bind only a loopback address")]
    PlaintextBeyondLoopback,
    /// The build ended abnormally.
    #[error("the listener build ended abnormally: {0}")]
    Task(String),
    /// The listener's OAuth sign-in is not available yet.
    #[error("the {listener} listener's OAuth sign-in is not available")]
    SignInUnavailable {
        /// `main` or `dedicated`.
        listener: &'static str,
    },
    /// The client CA of the listener's client-certificate sign-in is missing or unusable.
    #[error("client CA {0}")]
    ClientCa(String),
    /// The listener's identity provider sign-in (`oauth = "external"`) cannot run.
    #[error("identity provider: {0}")]
    IdentityProvider(ProviderRefusal),
}

impl From<AttachError> for BuildError {
    #[inline]
    fn from(error: AttachError) -> Self {
        Self::Metrics(error.to_string())
    }
}

/// Builds and validates the `kind` generation for `settings`; blocking (reads the keys,
/// the TLS files, and may write the dedicated listener's certificate).
// cancel-safe: synchronous.
pub(crate) fn build(
    shared: &Shared,
    kind: ListenerKind,
    settings: &McpConfig,
    keys: Keys,
) -> Result<Built, BuildError> {
    let (callback, handles) = oneshot::channel();
    let mtls = client_certificates(shared, settings, kind)?;
    let (oauth, activation) = tokens(shared, settings, kind)?;
    let base = kit_base(shared, keys, (mtls, oauth))?.with_reload_callback(move |handle| {
        drop(callback.send(handle));
    });
    let (server, bind, factory, probe) = match kind {
        ListenerKind::Main => main(shared, settings, base)?,
        ListenerKind::Dedicated | _ => dedicated(shared, settings, base)?,
    };
    Ok(Built {
        kind,
        settings: settings.clone(),
        config: server.validate()?,
        bind,
        factory,
        probe,
        handles,
        activation,
    })
}

/// What a listener-specific build adds to the shared base.
type Parts = (McpServerConfig, SocketAddr, Factory, Probe);

/// The main listener: `[server]`, the Web UI and its origins, metrics.
fn main(shared: &Shared, settings: &McpConfig, base: McpServerConfig) -> Result<Parts, BuildError> {
    let config = &shared.config;
    let tls = match (&config.server.tls_cert_path, &config.server.tls_key_path) {
        (Some(cert), Some(key)) => Some(leaf(cert, key)?),
        _ => None,
    };
    let mut server = crate::server_origins::apply(
        base.with_extra_route_rate_limit(600)
            .with_security_headers(security_headers(config.browser_transport_secure())),
        config,
    )?;
    if let Some(web) = &shared.web {
        server = server.with_extra_router(web_router(web.clone()));
    }
    let metrics = match &shared.metrics {
        Some(metrics) => {
            server = metrics.attach(server)?;
            Some(metrics.bind())
        }
        None => None,
    };
    let ip: IpAddr = config
        .server
        .listen_addr
        .trim_matches(['[', ']'])
        .parse()
        .map_err(|_invalid| {
            RmcpServerKitError::Config(format!(
                "server.listen_addr {:?} is not an IP address",
                config.server.listen_addr
            ))
        })?;
    let factory = if settings.endpoint == Endpoint::Dedicated {
        let mut without_tools = settings.clone();
        without_tools.toolsets.clear();
        Factory::Fixed(Arc::new(shared.live.load().reconfigured(without_tools)))
    } else {
        Factory::Live(Arc::clone(&shared.live))
    };
    let bind = SocketAddr::new(ip, config.server.listen_port);
    let probe = Probe::new(tls, metrics).with_mtls(settings.auth.main.mtls);
    Ok((server, bind, factory, probe))
}

/// The dedicated listener: `/mcp` only, its own address, URL and certificate; no Web UI
/// and no metrics.
fn dedicated(
    shared: &Shared,
    settings: &McpConfig,
    base: McpServerConfig,
) -> Result<Parts, BuildError> {
    let dedicated = &settings.dedicated;
    let server_tls = &shared.config.server;
    let paths = match dedicated.tls {
        DedicatedTls::Main => server_tls
            .tls_cert_path
            .clone()
            .zip(server_tls.tls_key_path.clone()),
        DedicatedTls::SelfSigned => Some(
            ensure(shared.state.dir(), dedicated)
                .map_err(|error| BuildError::Tls(error.to_string()))?,
        ),
        DedicatedTls::None | _ => None,
    };
    if paths.is_none() && !dedicated.bind.is_loopback() {
        return Err(BuildError::PlaintextBeyondLoopback);
    }
    let tls = paths
        .as_ref()
        .map(|(cert, key)| leaf(cert, key))
        .transpose()?;
    let bind = SocketAddr::new(dedicated.bind, dedicated.port);
    let (cert, key) = paths.unzip();
    let server = base
        .with_bind_addr(bind.to_string())
        .with_tls_paths(cert, key)
        .with_optional_public_url(
            dedicated
                .public_url
                .as_ref()
                .map(|url| url.as_str().trim_end_matches('/').to_owned()),
        )
        .with_security_headers(security_headers(tls.is_some()));
    let factory = Factory::Live(Arc::clone(&shared.live));
    let probe = Probe::new(tls, None).with_mtls(settings.auth.dedicated.mtls);
    Ok((server, bind, factory, probe))
}

/// `[server]` with the API keys, the client-certificate sign-in `mtls`, the token sign-in
/// `oauth`, the RBAC policy and the readiness probe.
fn kit_base(
    shared: &Shared,
    keys: Keys,
    (mtls, oauth): (Option<MtlsConfig>, Option<OAuthConfig>),
) -> Result<McpServerConfig, BuildError> {
    let entries = match (api_key_entries(&shared.state), keys) {
        (Ok(entries), _) => entries,
        (Err(error), Keys::Required) => return Err(BuildError::Keys(error.to_string())),
        (Err(error), Keys::BestEffort) => {
            tracing::error!(%error, "API keys unreadable; the listener refuses every key until the next reload");
            Vec::new()
        }
    };
    let base = McpServerConfig::new("placeholder:0", "kcc", env!("CARGO_PKG_VERSION"));
    let mut auth = AuthConfig::with_keys(entries)
        .with_rate_limit(RateLimitConfig::new(30).with_pre_auth_burst(10));
    auth.mtls = mtls;
    auth.oauth = oauth;
    Ok(shared
        .config
        .server
        .apply_to_mcp_config(base)?
        .with_auth(auth)
        .with_rbac(Arc::new(RbacPolicy::new(&shared.live.load().rbac_config())))
        .with_readiness_check(Arc::clone(&shared.readiness)))
}
