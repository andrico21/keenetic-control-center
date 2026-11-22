//! Audit entries of the SSH flows: router, actor, outcome and public facts only.

use kcc_app::audit::{AuditEvent, request_id};
use serde_json::{Value, json};

use super::{Caller, Facts, SshServices, error::EntwareError};

/// Request id prefix of the SSH flows.
const REQUEST_PREFIX: &str = "ssh";

/// An audited SSH flow.
#[derive(Clone, Copy, Debug)]
pub(super) enum Action {
    /// A host key probe.
    Probe,
    /// A first enrolment, or a retry from Pending.
    Bootstrap,
    /// An enrolment of a changed host key.
    Repin,
    /// Removal of kcc's key from the router and the local state.
    Revoke,
    /// Removal of the local state only.
    Disable,
    /// The installed package listing.
    PackagesList,
    /// The upgradable package listing.
    PackagesUpgradable,
    /// A package list update.
    Update,
    /// A package installation.
    Install,
    /// A package removal.
    Remove,
    /// A package upgrade.
    Upgrade,
    /// The service listing.
    ServicesList,
    /// A service's `check`.
    ServiceStatus,
    /// A service start.
    ServiceStart,
    /// A service stop.
    ServiceStop,
    /// A service restart.
    ServiceRestart,
}

impl Action {
    /// Whether the flow replaces a pinned host key (re-pin) rather than keeping it.
    pub(super) const fn replaces_pin(self) -> bool {
        match self {
            Self::Repin => true,
            Self::Probe
            | Self::Bootstrap
            | Self::Revoke
            | Self::Disable
            | Self::PackagesList
            | Self::PackagesUpgradable
            | Self::Update
            | Self::Install
            | Self::Remove
            | Self::Upgrade
            | Self::ServicesList
            | Self::ServiceStatus
            | Self::ServiceStart
            | Self::ServiceStop
            | Self::ServiceRestart => false,
        }
    }

    /// The audit action name, also the job kind of a mutation.
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Probe => "entware.ssh.probe",
            Self::Bootstrap => "entware.ssh.bootstrap",
            Self::Repin => "entware.ssh.repin",
            Self::Revoke => "entware.ssh.revoke",
            Self::Disable => "entware.ssh.disable",
            Self::PackagesList => "entware.ssh.packages_list",
            Self::PackagesUpgradable => "entware.ssh.packages_upgradable",
            Self::Update => "entware.ssh.update",
            Self::Install => "entware.ssh.install",
            Self::Remove => "entware.ssh.remove",
            Self::Upgrade => "entware.ssh.upgrade",
            Self::ServicesList => "entware.ssh.services_list",
            Self::ServiceStatus => "entware.ssh.service_status",
            Self::ServiceStart => "entware.ssh.service_start",
            Self::ServiceStop => "entware.ssh.service_stop",
            Self::ServiceRestart => "entware.ssh.service_restart",
        }
    }
}

impl Facts {
    /// No facts yet about `action`.
    pub(super) const fn new(action: Action) -> Self {
        Self {
            action,
            port: None,
            fingerprint: None,
            previous_fingerprint: None,
            default_password_in_use: None,
            entware_key_still_authorized: None,
            package: None,
            service: None,
            output_bytes: None,
            output_sha256: None,
        }
    }

    /// Appends the entry of the flow ending with `failure` (`None`: success), carrying
    /// these facts; a host key mismatch adds an `entware.ssh.hostkey_mismatch` entry with
    /// both fingerprints. A write failure is logged: the step's own outcome stands.
    // NOT cancel-safe: an entry may be appended after cancellation while awaiting the writer.
    pub(super) async fn record(
        &self,
        services: &SshServices,
        caller: &Caller<'_>,
        failure: Option<&EntwareError>,
    ) {
        let (name, router) = (self.action.name(), caller.router);
        let now = services.clock.unix_seconds();
        let mut params = serde_json::to_value(self)
            .ok()
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        let outcome = failure.map_or_else(
            || "success".to_owned(),
            |error| {
                let attempt = AuditEvent::attempt(
                    now,
                    caller.actor.clone(),
                    name.to_owned(),
                    Some(router.to_owned()),
                    error.attempt(),
                );
                if let Some(reason) = attempt.params_redacted.as_object() {
                    params.extend(reason.clone());
                }
                attempt.outcome
            },
        );
        let event = AuditEvent::new(now, caller.actor.clone(), name.to_owned())
            .with_router(router.to_owned())
            .with_params(Value::Object(params))
            .with_result(outcome, request_id::next(REQUEST_PREFIX));
        append(services, event).await;
        if let Some((expected, actual)) = failure.and_then(EntwareError::mismatch) {
            let mismatch = AuditEvent::new(
                now,
                caller.actor.clone(),
                "entware.ssh.hostkey_mismatch".to_owned(),
            )
            .with_router(router.to_owned())
            .with_params(json!({
                "operation": name,
                "expected": expected,
                "actual": actual,
            }))
            .with_result("refused".to_owned(), request_id::next(REQUEST_PREFIX));
            append(services, mismatch).await;
        }
    }
}

/// Appends `event`, logging a failure.
// NOT cancel-safe: the event may be appended after cancellation while awaiting the writer.
async fn append(services: &SshServices, event: AuditEvent) {
    if let Err(error) = services.audit.append(event).await {
        tracing::warn!(%error, "Entware SSH audit entry not written");
    }
}
