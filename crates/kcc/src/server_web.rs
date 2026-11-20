//! The Web UI of `kcc serve`, built on the server's shared services.
#![expect(
    clippy::missing_errors_doc,
    reason = "binary assembly: the startup error is reported by `kcc serve`, not an API caller"
)]

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::settings::Config;
use kcc_i18n::locale::Locale;
use kcc_telemetry::logs::runtime::Service as LogService;
use kcc_web::{
    WebState, WebStateConfig,
    admin::{AdminServices, ServerFacts, TransportReload},
    admin_notify::NotifyControl,
    fleet::{BackupServices, FleetServices, UpdateCheck},
    fleet_updates::ComponentsUpdateCheck,
    session::CookieSecurity,
};

use crate::{server_error::ServerError, server_services::Services};

/// Builds the authenticated Web UI around the same fleet services.
///
/// Administration changes reach the running MCP transport through `auth_reload`, and the
/// notifications page reaches the running notifier through `notify`.
pub(crate) fn web_state(
    services: &Services,
    config: &Config,
    auth_reload: Arc<TransportReload>,
    notify: Arc<dyn NotifyControl>,
) -> Result<WebState, ServerError> {
    let default_locale =
        Locale::from_tag(&config.web.default_locale).ok_or(ServerError::UnsupportedLocale)?;
    let update_check: Arc<dyn UpdateCheck> = Arc::<ComponentsUpdateCheck>::clone(&services.updates);
    let cookie_security = if config.browser_transport_secure() {
        CookieSecurity::Tls
    } else {
        CookieSecurity::LoopbackHttp
    };
    Ok(WebState::new(WebStateConfig {
        default_locale,
        accounts: Arc::clone(&services.accounts),
        audit: services.audit.clone(),
        roles: services.roles.current().to_vec(),
        session_idle: config.web.session_idle,
        session_absolute: config.web.session_absolute,
        allowed_origins: config.web_allowed_origins()?,
        cookie_security,
        clock: Arc::clone(&services.clock),
    })
    .with_role_source(services.roles.clone())
    .with_log_feeds(services.logs.as_ref().map_or_default(LogService::feeds))
    .with_fleet(FleetServices {
        registry: Arc::clone(&services.registry),
        poller: Arc::clone(&services.poller),
        workflow: Arc::clone(&services.workflow),
        credentials: Arc::clone(&services.credentials),
        update_check: Some(update_check),
        backups: Some(BackupServices::new(
            Arc::clone(&services.backups),
            config.backups,
        )),
    })
    .with_jobs(Arc::clone(&services.jobs))
    .with_admin(AdminServices {
        state: services.state.clone(),
        reload: Some(auth_reload),
        server: ServerFacts::from_config(env!("CARGO_PKG_VERSION").to_owned(), config),
    })
    .with_notify(notify))
}
