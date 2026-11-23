//! The SSH access section of the Entware page: enrolment, and the packages and services
//! kcc manages over SSH once the enrolment is Active.
//!
//! Every SSH action needs `Destructive` on the router: a role without it sees no section
//! and its requests are refused before anything reaches the router. Each action asks for
//! the router name first, as the kit does for destructive changes. The enrolment steps
//! run inline; package and service changes run as jobs followed through the job feed.
//!
//! - `POST .../entware/ssh/enabled?on=true|false`, `POST .../entware/ssh/port`: SSH
//!   management switched and its port set, locally.
//! - `POST .../entware/ssh/probe?mode=bootstrap|repin`: step 1, the host key fingerprint
//!   with its single-use ticket; `POST .../entware/ssh/bootstrap|repin`: step 2, the
//!   fingerprint confirmed with the Entware root password.
//! - `POST .../entware/ssh/revoke`, `POST .../entware/ssh/disable`.
//! - `POST .../entware/ssh/packages/{op}` and `POST .../entware/ssh/services/{op}`.

use alloc::sync::Arc;
use core::time::Duration;
use std::sync::OnceLock;

use askama::Template;
use axum::{Router, routing::post};
use kcc_app::{
    entware_ssh::state::{DEFAULT_PORT, EnrolmentState, SshEnrolment, SshStore},
    permissions::Permission,
};
use kcc_domain::entware::{
    models::{EntwareStatus, Possibility},
    ssh::SshServices,
};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_ssh::transport::Timeouts;

use super::{
    entware_ssh_confirm as confirm, entware_ssh_enrol as enrol, entware_ssh_ops as ops,
    entware_ssh_services as services,
};
use crate::{
    WebState,
    authz::CurrentUser,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::allowed},
};

/// How long a page waits for an SSH list, status or log: below the request timeout, so
/// a read waiting for a running change answers that the router is busy.
const READ_LIMIT: Duration = Duration::from_secs(25);

/// The Web UI's SSH services, built over the fleet at their first use, and their bounds.
pub(crate) struct SshAccess {
    /// Connection and command bounds of the services.
    timeouts: Timeouts,
    /// How long a page waits for a read.
    read_limit: Duration,
    /// The services, once built.
    services: OnceLock<Arc<SshServices>>,
}

impl Default for SshAccess {
    fn default() -> Self {
        Self::new(Timeouts::default(), READ_LIMIT)
    }
}

impl SshAccess {
    /// Services bounded by `timeouts`, whose reads a page waits `read_limit` for.
    pub(crate) const fn new(timeouts: Timeouts, read_limit: Duration) -> Self {
        Self {
            timeouts,
            read_limit,
            services: OnceLock::new(),
        }
    }

    /// How long a page waits for a read.
    pub(crate) const fn read_limit(&self) -> Duration {
        self.read_limit
    }

    /// The services over `state`'s fleet, its audit log and clock; `None` without a
    /// fleet.
    pub(crate) fn services(&self, state: &WebState) -> Option<Arc<SshServices>> {
        let fleet = state.fleet()?;
        let built = self.services.get_or_init(|| {
            let workflow = fleet.workflow();
            Arc::new(
                SshServices::new(
                    Arc::clone(workflow),
                    Arc::clone(fleet.registry()),
                    state.audit().clone(),
                    workflow.backups().key(),
                    state.clock(),
                )
                .with_timeouts(self.timeouts),
            )
        });
        Some(Arc::clone(built))
    }
}

/// The sealed SSH records of `state`'s fleet; `None` without a fleet.
pub(crate) fn store(state: &WebState) -> Option<SshStore> {
    let workflow = state.fleet()?.workflow();
    Some(SshStore::new(
        workflow.state().clone(),
        workflow.backups().key().duplicate(),
    ))
}

/// The enrolment as the section shows it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shown {
    /// Nothing pinned: never enrolled, forgotten, or the router's address changed.
    Unenrolled,
    /// A pin saved, not confirmed by a key-only session yet.
    Pending,
    /// Enrolled.
    Active,
    /// A record that cannot be opened.
    Unreadable,
}

impl Shown {
    /// The stable `data-state` word.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Unenrolled => "none",
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Unreadable => "unreadable",
        }
    }

    /// The label.
    pub(crate) const fn key(self) -> MessageKey {
        match self {
            Self::Unenrolled => keys::WEB_SYSTEM_ENTWARE_SSH_STATE_NONE,
            Self::Pending => keys::WEB_SYSTEM_ENTWARE_SSH_STATE_PENDING,
            Self::Active => keys::WEB_SYSTEM_ENTWARE_SSH_STATE_ACTIVE,
            Self::Unreadable => keys::WEB_SYSTEM_ENTWARE_SSH_STATE_UNREADABLE,
        }
    }
}

/// The SSH access section, and the package and service sections once Active.
#[derive(Template)]
#[template(path = "partials/system_entware_ssh.html")]
pub(crate) struct SshSection {
    /// Locale carrier.
    shell: Shell,
    /// The section's actions, `/ui/r/{router}/system/entware/ssh`.
    base: String,
    /// The enrolment.
    shown: Shown,
    /// The record, when one exists.
    record: Option<SshEnrolment>,
    /// Whether `opkg chroot` is on, which stops every SSH action.
    chroot: bool,
}

localized!(SshSection);
fragment!(SshSection);

impl SshSection {
    /// Whether SSH management is on; a router without a record is on by default.
    pub(crate) fn enabled(&self) -> bool {
        self.record.as_ref().is_none_or(|record| record.enabled)
    }

    /// The port kcc connects to.
    pub(crate) fn port(&self) -> u16 {
        self.record
            .as_ref()
            .map_or(DEFAULT_PORT, |record| record.port)
    }

    /// The pinned host key's fingerprint.
    pub(crate) fn pinned(&self) -> Option<&str> {
        self.record.as_ref()?.fingerprint.as_deref()
    }

    /// Who enrolled the router.
    pub(crate) fn enrolled_by(&self) -> Option<&str> {
        self.record.as_ref()?.enrolled_by.as_deref()
    }

    /// Whether the identity check and the steps after it are offered.
    pub(crate) fn checks(&self) -> bool {
        self.enabled() && !self.chroot && self.shown != Shown::Unreadable
    }

    /// Whether the package and service sections are offered: Active, on, chroot off.
    pub(crate) fn manages(&self) -> bool {
        self.checks() && self.shown == Shown::Active
    }
}

/// The section `user` sees on `router` in the Entware `status`: only with `Destructive`
/// on the router, on a router that runs Entware.
pub(crate) fn section(
    state: &WebState,
    user: &CurrentUser,
    router: &str,
    status: &EntwareStatus,
) -> Option<SshSection> {
    let offered = status.possible == Possibility::Possible
        && status.settings.disk.is_some()
        && allowed(user, router, &[Permission::Destructive]);
    if !offered {
        return None;
    }
    let (shown, record) = match store(state)?.load(router) {
        Ok(None) => (Shown::Unenrolled, None),
        Ok(Some(record)) if record.state == EnrolmentState::Active => (Shown::Active, Some(record)),
        Ok(Some(record)) if record.fingerprint.is_some() => (Shown::Pending, Some(record)),
        Ok(Some(record)) => (Shown::Unenrolled, Some(record)),
        Err(error) => {
            tracing::warn!(%error, "Entware SSH state could not be read");
            (Shown::Unreadable, None)
        }
    };
    Some(SshSection {
        shell: fragment_shell(user.locale()),
        base: format!("/ui/r/{router}/system/entware/ssh"),
        shown,
        record,
        chroot: status.settings.chroot,
    })
}

/// The routes of the SSH section.
pub(crate) fn routes() -> Router<WebState> {
    let at = |tail: &str| format!("/ui/r/{{router}}/system/entware/ssh/{tail}");
    Router::new()
        .route(&at("enabled"), post(enrol::enabled))
        .route(&at("port"), post(enrol::port))
        .route(&at("probe"), post(enrol::probe))
        .route(&at("bootstrap"), post(confirm::bootstrap))
        .route(&at("repin"), post(confirm::repin))
        .route(&at("revoke"), post(enrol::revoke))
        .route(&at("disable"), post(enrol::disable))
        .route(&at("packages/{op}"), post(ops::packages))
        .route(&at("services/{op}"), post(services::services))
}
