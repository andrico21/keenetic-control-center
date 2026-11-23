//! `GET /ui/admin/mcp` and the region every change answers with.

extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;
use std::fs;

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};
use kcc_app::mcp_settings::{
    client_ca::{self, CaError, mtls_ca_subjects},
    document::McpSettingsDocument,
};
use kcc_i18n::{keys, locale::Locale};
use tokio::task::spawn_blocking;

use super::{Facts, Progress, pem, status::Status, upload::mtls_users, view::Region};
use crate::{
    WebState,
    admin_shared::{Tab, TabLink, tabs, unavailable},
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::context::Caller,
};

/// A failure reading the state behind the page.
pub(crate) type Failure = Box<dyn Error + Send + Sync>;

/// The state subdirectory with the MCP certificate files.
pub(crate) const DIRECTORY: &str = "mcp";

/// The dedicated listener's self-signed certificate.
pub(crate) const CERTIFICATE: &str = "dedicated-cert.pem";

/// The uploaded client CA.
pub(crate) const MTLS_CA: &str = client_ca::MTLS_CA;

/// The uploaded CA bundle of the identity provider.
pub(crate) const OIDC_CA: &str = "oidc-ca.pem";

/// The MCP settings page.
#[derive(Template)]
#[template(path = "pages/admin_mcp.html")]
struct McpPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// The restart status.
    status: Status,
    /// Every section.
    region: Region,
}

localized!(McpPage);

/// `GET /ui/admin/mcp`.
// cancel-safe: it only reads local state on a blocking thread.
pub(crate) async fn page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Admin, None)
        .await;
    if state.admin().is_none() {
        return unavailable(Some(shell));
    }
    let locale = user.locale();
    match fresh(&state, &user).await {
        Ok(region) => errors::render(&McpPage {
            tabs: tabs(user.role(), Tab::Mcp),
            status: status_now(&state, locale),
            region: region.inline(),
            shell,
        }),
        Err(error) => errors::internal(&*error, shell),
    }
}

/// The restart status as it stands, polling until a restart's longest time from now.
pub(crate) fn status_now(state: &WebState, locale: Locale) -> Status {
    let progress = state
        .mcp()
        .map_or(Progress::Idle, |attached| attached.progress());
    Status::new(locale, &progress, deadline(state))
}

/// Now and the last second a restart started now is polled.
pub(crate) fn deadline(state: &WebState) -> (u64, u64) {
    let now = state.unix_seconds();
    let window = state
        .admin()
        .map_or(0, |admin| admin.server().restart_window().as_secs());
    (now, now.saturating_add(window))
}

/// The region read again for `user`, sent out of band.
///
/// It is in their locale, offers the roles they may assign, and carries the revision it
/// shows, read before the settings so a form never claims a newer revision than its
/// values.
///
/// # Errors
///
/// The settings or the state directory could not be read.
// cancel-safe: it only reads local state on a blocking thread.
pub(crate) async fn fresh(state: &WebState, user: &CurrentUser) -> Result<Region, Failure> {
    let locale = user.locale();
    let admin = state.admin().ok_or("no administration services")?;
    let (store, base) = (admin.state().clone(), admin.mcp().clone());
    let (revision, effective, (fingerprint, cas, subjects)) = spawn_blocking(move || {
        let revision = store
            .read::<McpSettingsDocument>()?
            .unwrap_or_default()
            .revision;
        let effective = base.effective(&store)?;
        let dir = store.dir().join(DIRECTORY);
        let fingerprint = fs::read(dir.join(CERTIFICATE))
            .ok()
            .and_then(|bytes| pem::fingerprint(&bytes));
        let cas = (dir.join(MTLS_CA).is_file(), dir.join(OIDC_CA).is_file());
        let subjects = match mtls_ca_subjects(&store) {
            Ok(subjects) => Some(subjects.unwrap_or_default()),
            Err(CaError::State(error)) => return Err(error.into()),
            Err(_unchecked) => None,
        };
        Ok::<_, Failure>((revision, effective, (fingerprint, cas, subjects)))
    })
    .await??;
    let roles = state.roles();
    let actor = user.role();
    let attached = state.mcp().map(Arc::clone);
    let facts = Facts {
        status: attached.as_ref().map(|mcp| mcp.control().status()),
        toolsets: attached
            .as_ref()
            .map_or_default(|mcp| mcp.control().toolsets()),
        roles: roles.iter().map(|role| role.name.clone()).collect(),
        assignable: roles
            .iter()
            .filter(|role| actor.dominates(role))
            .map(|role| role.name.clone())
            .collect(),
        issuer: admin.server().issuer().clone(),
        fingerprint,
        cas,
        subjects,
        mtls_users: mtls_users(effective.settings()),
        revision,
    };
    Ok(Region::new(locale, &effective, facts))
}
