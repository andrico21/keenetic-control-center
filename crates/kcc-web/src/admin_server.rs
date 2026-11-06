//! The server summary at `/ui/admin/server` (`ManageUsers`): version and uptime, the
//! configuration without secrets, the state directory's health and the command catalogs
//! built into this binary.

extern crate alloc;

use alloc::collections::BTreeMap;
use std::{fs::OpenOptions, path::Path};

use askama::Template;
use axum::{extract::State, http::HeaderMap, response::Response};
use kcc_catalog::generated::FILES;
use kcc_i18n::{bundle::tr, format, keys};
use tokio::task::spawn_blocking;

use crate::{
    WebState,
    admin_shared::{Tab, TabLink, Timestamp, tabs, unavailable},
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize, Shell},
    page_kit::context::Caller,
};

/// One firmware line of the built-in command catalog.
struct CatalogLine {
    /// Firmware line, such as `5.1`.
    version: String,
    /// Command groups described for it.
    groups: String,
}

/// The server page.
#[derive(Template)]
#[template(path = "pages/admin_server.html")]
struct ServerPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// Release version.
    version: String,
    /// Process start.
    started: Option<Timestamp>,
    /// Time since the start.
    uptime: String,
    /// Configuration summary: label and value.
    summary: Vec<(String, String)>,
    /// State directory path.
    state_dir: String,
    /// Whether kcc can write to the state directory.
    writable: String,
    /// Whether the audit writer accepts entries.
    audit_writer: String,
    /// Built-in command catalog lines.
    catalogs: Vec<CatalogLine>,
}

impl Localize for ServerPage {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// `GET /ui/admin/server`.
pub(crate) async fn page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Admin, None)
        .await;
    let Some(admin) = state.admin() else {
        return unavailable(Some(shell));
    };
    let locale = user.locale();
    let dir = admin.state().dir().to_owned();
    let writable = match spawn_blocking(move || writable(&dir)).await {
        Ok(writable) => writable,
        Err(error) => return errors::internal(&error, shell),
    };
    let yes_no = |value: bool| {
        tr(
            locale,
            if value {
                keys::COMMON_YES
            } else {
                keys::COMMON_NO
            },
            None,
        )
    };
    let server = admin.server();
    let page = ServerPage {
        tabs: tabs(user.role(), Tab::Server),
        version: server.version().to_owned(),
        started: Timestamp::at(admin.started_at()),
        uptime: format::duration(
            locale,
            state.unix_seconds().saturating_sub(admin.started_at()),
        ),
        summary: server.summary(locale),
        state_dir: admin.state().dir().display().to_string(),
        writable: yes_no(writable),
        audit_writer: tr(
            locale,
            if state.audit().is_alive() {
                keys::WEB_ADMIN_SERVER_RUNNING
            } else {
                keys::WEB_ADMIN_SERVER_STOPPED
            },
            None,
        ),
        catalogs: catalogs(&shell),
        shell,
    };
    errors::render(&page)
}

/// Whether `<dir>/.ready` opens for appending, the readiness probe's own check.
fn writable(dir: &Path) -> bool {
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(".ready"))
    {
        Ok(_probe) => true,
        Err(error) => {
            tracing::warn!(%error, "state directory is not writable");
            false
        }
    }
}

/// The firmware lines of the built-in catalog with their command-group counts.
fn catalogs(shell: &Shell) -> Vec<CatalogLine> {
    let mut lines: BTreeMap<&str, u64> = BTreeMap::new();
    for (path, _) in FILES {
        if let Some(version) = path
            .strip_prefix("catalog/")
            .and_then(|rest| rest.split_once('/'))
            .map(|(version, _)| version)
        {
            let count = lines.entry(version).or_default();
            *count = count.saturating_add(1);
        }
    }
    lines
        .into_iter()
        .map(|(version, groups)| CatalogLine {
            version: version.to_owned(),
            groups: format::integer(shell.locale(), groups),
        })
        .collect()
}
