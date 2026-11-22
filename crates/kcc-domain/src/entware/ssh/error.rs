//! Refusals and failures of the Entware SSH flows.

use kcc_app::{
    audit::{Attempt, AuditError},
    entware_ssh::{SshStateError, TicketRefusal},
    jobs::JobError,
    workflow::WorkflowError,
};
use kcc_ssh::{error::SshError, parse::ServiceState};

use crate::DomainError;

/// A refusal or failure of an Entware SSH flow.
///
/// No variant carries a password, a private key, a nonce or command output; a host key
/// mismatch carries the two public fingerprints.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers name it next to other crates' errors as EntwareError"
)]
pub enum EntwareError {
    /// The role lacks `Permission::Destructive` or the router scope; nothing was sent.
    #[error("permission denied for Entware SSH management")]
    PermissionDenied,
    /// Probe, bootstrap, re-pin and revoke are not available to MCP callers.
    #[error("Entware SSH enrolment is not available over MCP")]
    McpRefused,
    /// `opkg chroot` is on: kcc's absolute paths do not exist in SSH sessions.
    #[error("opkg chroot is on, so Entware cannot be managed over SSH")]
    ChrootEnabled,
    /// The router URL host differs from the enrolled one; the pin was cleared.
    #[error("the router URL host changed: probe and bootstrap Entware SSH again")]
    RouterHostChanged,
    /// Nothing is pinned (re-pin), or no pin or key is stored (revoke).
    #[error("Entware SSH is not enrolled for this router")]
    NotEnrolled,
    /// The probed host key differs from the pinned one; a bootstrap cannot replace it.
    #[error("the Entware host key differs from the pinned one: re-pin it")]
    RepinRequired,
    /// A re-pin was asked for the key that is already pinned.
    #[error("the Entware host key is unchanged: nothing to re-pin")]
    HostKeyUnchanged,
    /// The router write lease or the audit check refused the step.
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    /// Reading the router over RCI failed.
    #[error(transparent)]
    Domain(#[from] DomainError),
    /// The sealed SSH state or the probe ticket refused or failed.
    #[error(transparent)]
    State(#[from] SshStateError),
    /// The SSH connection or a command failed.
    #[error(transparent)]
    Ssh(#[from] SshError),
    /// Revoke could not remove kcc's key over SSH; the local state is kept.
    #[error(
        "kcc could not remove its key over SSH ({0}); disable forgets the key locally and \
         leaves it authorized on the router"
    )]
    RevokeFailed(SshError),
    /// Revoke could not read the router over RCI before connecting; the local state is
    /// kept.
    #[error(
        "kcc could not reach the router to remove its key ({0}); disable forgets the key \
         locally and leaves it authorized on the router"
    )]
    RevokeUnreachable(DomainError),
    /// The audit log cannot record the step.
    #[error(transparent)]
    Audit(#[from] AuditError),
    /// SSH management of the router is switched off; nothing was sent.
    #[error("Entware SSH management is switched off for this router")]
    SshDisabled,
    /// A removal or upgrade names a package the router's installed listing lacks; no
    /// mutating command was sent.
    #[error("the Entware package {package} is not installed")]
    PackageNotInstalled {
        /// The package name.
        package: String,
    },
    /// A service operation names a service the router's service listing lacks; no
    /// action was sent.
    #[error("the router has no Entware service {service}")]
    UnknownService {
        /// The init script name.
        service: String,
    },
    /// rc.func refused to start a service whose `ENABLED` is not `yes` (exit 8); `state`
    /// is what `check` read afterwards (a restart has stopped it).
    #[error("the Entware service {service} is disabled; it is now {}", state_word(*.state))]
    ServiceDisabled {
        /// The init script name.
        service: String,
        /// The service's state after the action.
        state: ServiceState,
    },
    /// A mutation job could not be started.
    #[error(transparent)]
    Job(#[from] JobError),
}

impl EntwareError {
    /// The audited shape of this outcome, with a stable reason or error code.
    pub(super) const fn attempt(&self) -> Attempt {
        match self {
            Self::PermissionDenied => Attempt::Forbidden,
            Self::McpRefused => refused("mcp"),
            Self::ChrootEnabled => refused("chroot_enabled"),
            Self::RouterHostChanged => refused("router_host_changed"),
            Self::NotEnrolled => refused("not_enrolled"),
            Self::RepinRequired => refused("repin_required"),
            Self::HostKeyUnchanged => refused("host_key_unchanged"),
            Self::Workflow(WorkflowError::RouterBusy { actor: _ }) => refused("router_busy"),
            Self::State(SshStateError::Ticket(refusal)) => refused(ticket_reason(*refusal)),
            Self::Ssh(SshError::HostKeyMismatch {
                expected: _,
                actual: _,
            })
            | Self::RevokeFailed(SshError::HostKeyMismatch {
                expected: _,
                actual: _,
            }) => refused("hostkey_mismatch"),
            Self::Ssh(SshError::AuthRejected) => refused("auth_rejected"),
            Self::SshDisabled => refused("ssh_disabled"),
            Self::PackageNotInstalled { package: _ } => refused("package_not_installed"),
            Self::UnknownService { service: _ } => refused("unknown_service"),
            Self::ServiceDisabled {
                service: _,
                state: _,
            } => refused("service_disabled"),
            Self::Workflow(WorkflowError::VerificationFailed { field: _ }) => {
                failed("verification")
            }
            Self::Workflow(_) => failed("workflow"),
            Self::Domain(_) | Self::RevokeUnreachable(_) => failed("router"),
            Self::State(_) => failed("state"),
            Self::Ssh(_) | Self::RevokeFailed(_) => failed("ssh"),
            Self::Audit(_) => failed("audit"),
            Self::Job(_) => failed("job"),
        }
    }

    /// The two fingerprints of a host key mismatch.
    pub(super) const fn mismatch(&self) -> Option<(&String, &String)> {
        match self {
            Self::Ssh(SshError::HostKeyMismatch { expected, actual })
            | Self::RevokeFailed(SshError::HostKeyMismatch { expected, actual }) => {
                Some((expected, actual))
            }
            Self::PermissionDenied
            | Self::McpRefused
            | Self::ChrootEnabled
            | Self::RouterHostChanged
            | Self::NotEnrolled
            | Self::RepinRequired
            | Self::HostKeyUnchanged
            | Self::Workflow(_)
            | Self::Domain(_)
            | Self::State(_)
            | Self::Ssh(_)
            | Self::RevokeFailed(_)
            | Self::RevokeUnreachable(_)
            | Self::Audit(_)
            | Self::SshDisabled
            | Self::PackageNotInstalled { package: _ }
            | Self::UnknownService { service: _ }
            | Self::ServiceDisabled {
                service: _,
                state: _,
            }
            | Self::Job(_) => None,
        }
    }
}

/// A refusal with `reason`.
const fn refused(reason: &'static str) -> Attempt {
    Attempt::Refused { reason }
}

/// A failure with `error`; no SSH flow arms a recovery timer.
const fn failed(error: &'static str) -> Attempt {
    Attempt::Failed {
        error,
        fail_safe_armed: false,
    }
}

/// A service state as a word.
const fn state_word(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Running => "running",
        ServiceState::Stopped => "stopped",
        _ => "in an unknown state",
    }
}

/// The audit reason of a ticket refusal.
const fn ticket_reason(refusal: TicketRefusal) -> &'static str {
    match refusal {
        TicketRefusal::Missing => "ticket_missing",
        TicketRefusal::Expired => "ticket_expired",
        TicketRefusal::Port => "ticket_port",
        TicketRefusal::Actor => "ticket_actor",
        TicketRefusal::Nonce => "ticket_nonce",
        TicketRefusal::Fingerprint => "ticket_fingerprint",
        _ => "ticket",
    }
}
