//! The services a fixture's supervisor uses: the MCP handler and the Web UI.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    accounts::{AccountStore, Clock, NewAccount, SystemClock},
    audit::AuditLog,
    backups::BackupStore,
    jobs::JobRunner,
    mcp_settings::Effective,
    permissions::Role,
    persist::StateStore,
    poller::Poller,
    registry::RouterRegistry,
    secrets::MasterKey,
    settings::{Config, OutboundConfig, PrivacyConfig},
    workflow::ChangeWorkflow,
};
use kcc_i18n::locale::Locale;
use kcc_mcp::KccMcp;
use kcc_web::{WebState, WebStateConfig, session::CookieSecurity};
use secrecy::SecretString;

use super::{TestResult, fixture::PASSWORD};

/// The MCP handler on `effective` over an empty router registry, and its poller.
pub(super) async fn handler(
    state: &StateStore,
    (effective, audit): (&Effective, &AuditLog),
    (roles, admin): (&[Role], &Role),
) -> TestResult<(KccMcp, Arc<Poller>)> {
    let registry = Arc::new(RouterRegistry::new(
        state.clone(),
        &[],
        &OutboundConfig::default(),
    )?);
    let workflow = ChangeWorkflow::new(
        state.clone(),
        Arc::clone(&registry),
        Arc::new(BackupStore::new(
            state.clone(),
            MasterKey::from_bytes([3_u8; 32]),
        )),
        audit.clone(),
    );
    let jobs = JobRunner::open(state.clone(), Arc::clone(&registry), audit.clone()).await?;
    let poller = Poller::new(Arc::clone(&registry));
    let handler = KccMcp::new(
        effective.settings().clone(),
        PrivacyConfig::default(),
        registry,
        workflow,
        jobs,
        Arc::clone(&poller),
        roles.to_vec(),
        admin.clone(),
    );
    Ok((handler, poller))
}

/// The Web UI with the account `alice` (role admin).
pub(super) fn web(
    state: &StateStore,
    config: &Config,
    audit: &AuditLog,
    (roles, admin): (Vec<Role>, &Role),
) -> TestResult<WebState> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    let accounts = Arc::new(AccountStore::new(
        state.clone(),
        MasterKey::from_bytes([5_u8; 32]),
        Duration::from_mins(15),
        Arc::clone(&clock),
    ));
    accounts.create(
        admin,
        NewAccount::new(
            "alice".to_owned(),
            SecretString::from(PASSWORD),
            "admin".to_owned(),
        ),
    )?;
    Ok(WebState::new(WebStateConfig {
        default_locale: Locale::En,
        accounts,
        audit: audit.clone(),
        roles,
        session_idle: config.web.session_idle,
        session_absolute: config.web.session_absolute,
        allowed_origins: config.web_allowed_origins()?,
        cookie_security: CookieSecurity::LoopbackHttp,
        clock,
    }))
}
