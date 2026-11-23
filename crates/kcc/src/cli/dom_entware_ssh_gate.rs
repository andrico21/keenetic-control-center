//! What every Entware SSH command shares: the destructive gate before any contact, the
//! SSH services, the read deadline, the failure of each refusal class and the cleaning
//! of router-reported text.

extern crate alloc;

use alloc::sync::Arc;
use core::time::Duration;

use kcc_app::{
    accounts::SystemClock,
    audit::Actor,
    entware_ssh::{SshStateError, TicketRefusal},
    permissions::{Permission, Role},
    workflow::WorkflowError,
};
use kcc_catalog::Risk;
use kcc_domain::entware::ssh::{Caller, SshServices, error::EntwareError};
use kcc_i18n::{bundle::MessageKey, keys};
use kcc_ssh::{error::SshError, parse::ServiceState};
use tokio::time::timeout;

use super::{
    context::{Ctx, Services, Target},
    exit::{Exit, Failure, Outcome, denied},
    output::Out,
    secret::confirm,
};

/// How long a read may take in all, sign-in and connection included: shorter than the
/// SSH read timeout, so a router that holds the session answers as slow or busy.
const READ_DEADLINE: Duration = Duration::from_secs(25);

/// One command past the destructive gate: the principal holds `Destructive` on the
/// router and confirmed its id; no router or SSH server was contacted yet.
#[derive(Debug)]
pub(crate) struct Opened {
    /// Application services.
    services: Services,
    /// The router id.
    id: String,
    /// The principal's role narrowed to the router.
    role: Role,
    /// The audited principal.
    actor: Actor,
}

/// Authorizes `Destructive` on the router, then asks for its id
/// (`--confirm-destructive`); both refusals are audited and happen before any router
/// request or SSH connection.
///
/// # Errors
///
/// Returns the policy refusal (exit 10), or service failures.
// NOT cancel-safe: a refusal audit may append after cancellation.
pub(crate) async fn open(ctx: &Ctx) -> Outcome<Opened> {
    let services = ctx.services().await?;
    let id = ctx.router_id(&services)?;
    let role = ctx
        .authorize_audited(&services, &[Permission::Destructive], &[&id])
        .await?;
    let confirmation = confirm(ctx.out(), ctx.globals(), Risk::Destructive, &id, false);
    ctx.confirmed(&services, &id, confirmation).await?;
    Ok(Opened {
        services,
        id,
        role,
        actor: ctx.principal().actor(),
    })
}

impl Opened {
    /// The router id.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The application services.
    pub(crate) const fn services(&self) -> &Services {
        &self.services
    }

    /// The caller of the domain flows.
    pub(crate) fn caller(&self) -> Caller<'_> {
        Caller::new(&self.id, &self.actor, &self.role)
    }

    /// The SSH services over this invocation's state; tickets live in the state
    /// directory, so a probe and a bootstrap may run in two invocations.
    pub(crate) fn ssh(&self) -> SshServices {
        let services = &self.services;
        SshServices::new(
            Arc::clone(services.workflow()),
            Arc::clone(services.registry()),
            services.audit_log().clone(),
            services.key(),
            Arc::new(SystemClock::default()),
        )
    }

    /// Connects to the router.
    ///
    /// # Errors
    ///
    /// Returns connection and detection failures.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an
    // orphaned router session.
    pub(crate) async fn target(&self, ctx: &Ctx) -> Outcome<Target> {
        ctx.target_named(&self.services, self.id.clone(), &[Permission::Destructive])
            .await
    }

    /// Awaits the read `read` for at most the read deadline.
    ///
    /// # Errors
    ///
    /// Returns the read's failure, or the 'slow or busy' failure (exit 5) past the
    /// deadline.
    // NOT cancel-safe: the read may sign in first.
    pub(crate) async fn read<T, F>(&self, out: Out, read: F) -> Outcome<T>
    where
        F: Future<Output = Result<T, EntwareError>>,
    {
        timeout(READ_DEADLINE, read)
            .await
            .map_err(|_elapsed| self.message(Exit::Conflict, keys::CLI_ENTWARE_SSH_SLOW))?
            .map_err(|error| self.failure(out, error))
    }

    /// A localized failure naming the router.
    fn message(&self, exit: Exit, key: MessageKey) -> Failure {
        Failure::message(exit, key, &[("router", &self.id)])
    }

    /// The failure of `error`, with its exit code.
    pub(crate) fn failure(&self, out: Out, error: EntwareError) -> Failure {
        let (exit, key) = match error {
            EntwareError::PermissionDenied => return denied(&self.id),
            EntwareError::ChrootEnabled => (Exit::Policy, keys::CLI_ENTWARE_SSH_CHROOT),
            EntwareError::NotEnrolled => (Exit::Policy, keys::CLI_ENTWARE_SSH_NOT_ENROLLED),
            EntwareError::SshDisabled => (Exit::Policy, keys::CLI_ENTWARE_SSH_DISABLED),
            EntwareError::RouterHostChanged => (Exit::Conflict, keys::CLI_ENTWARE_SSH_HOST_CHANGED),
            EntwareError::RepinRequired => (Exit::Conflict, keys::CLI_ENTWARE_SSH_REPIN_REQUIRED),
            EntwareError::HostKeyUnchanged => (Exit::Conflict, keys::CLI_ENTWARE_SSH_KEY_UNCHANGED),
            EntwareError::Workflow(WorkflowError::RouterBusy { actor: _ }) => {
                (Exit::Conflict, keys::CLI_ENTWARE_SSH_BUSY)
            }
            EntwareError::State(SshStateError::Ticket(refusal)) => {
                (Exit::Policy, ticket_key(refusal))
            }
            EntwareError::Ssh(SshError::AuthRejected) => {
                (Exit::Auth, keys::CLI_ENTWARE_SSH_AUTH_REJECTED)
            }
            EntwareError::Ssh(SshError::HostKeyMismatch {
                expected: _,
                actual,
            }) => {
                return Failure::message(
                    Exit::Policy,
                    keys::CLI_ENTWARE_SSH_HOSTKEY_MISMATCH,
                    &[("router", &self.id), ("value", &actual)],
                );
            }
            EntwareError::PackageNotInstalled { package } => {
                return self.named(
                    Exit::Validation,
                    keys::CLI_ENTWARE_PACKAGE_NOT_INSTALLED,
                    &package,
                );
            }
            EntwareError::UnknownService { service } => {
                return self.named(
                    Exit::Validation,
                    keys::CLI_ENTWARE_SERVICE_UNKNOWN,
                    &service,
                );
            }
            EntwareError::ServiceDisabled { service, state } => {
                let word = out.tr(state_key(state), &[]);
                return Failure::message(
                    Exit::Router,
                    keys::CLI_ENTWARE_SERVICE_DISABLED,
                    &[("router", &self.id), ("name", &service), ("value", &word)],
                );
            }
            EntwareError::Workflow(workflow) => return Failure::from(workflow),
            EntwareError::Domain(domain) => return Failure::from(domain),
            EntwareError::Ssh(SshError::NotAdmitted) | EntwareError::McpRefused => {
                return Failure::text(Exit::Policy, &error);
            }
            EntwareError::Ssh(_)
            | EntwareError::RevokeFailed(_)
            | EntwareError::RevokeUnreachable(_) => return Failure::text(Exit::Router, &error),
            EntwareError::Job(_) => return Failure::text(Exit::Conflict, &error),
            EntwareError::State(_) | EntwareError::Audit(_) | _ => {
                return Failure::text(Exit::Generic, &error);
            }
        };
        self.message(exit, key)
    }

    /// A failure naming the router and the package or service `name`.
    fn named(&self, exit: Exit, key: MessageKey, name: &str) -> Failure {
        Failure::message(exit, key, &[("router", &self.id), ("name", name)])
    }
}

/// The message of a ticket refusal.
const fn ticket_key(refusal: TicketRefusal) -> MessageKey {
    match refusal {
        TicketRefusal::Missing => keys::CLI_ENTWARE_SSH_TICKET_MISSING,
        TicketRefusal::Expired => keys::CLI_ENTWARE_SSH_TICKET_EXPIRED,
        TicketRefusal::Fingerprint => keys::CLI_ENTWARE_SSH_TICKET_FINGERPRINT,
        TicketRefusal::Port | TicketRefusal::Actor | TicketRefusal::Nonce | _ => {
            keys::CLI_ENTWARE_SSH_TICKET_INVALID
        }
    }
}

/// The localized word of a service state.
pub(crate) const fn state_key(state: ServiceState) -> MessageKey {
    match state {
        ServiceState::Running => keys::CLI_ENTWARE_SERVICE_RUNNING,
        ServiceState::Stopped | _ => keys::CLI_ENTWARE_SERVICE_STOPPED,
    }
}

/// The stable name of a service state.
pub(crate) const fn state_name(state: ServiceState) -> &'static str {
    match state {
        ServiceState::Running => "running",
        ServiceState::Stopped | _ => "stopped",
    }
}

/// `text` without control characters and bidirectional overrides: versions, names and
/// log lines come from the router and may carry terminal escapes or reorder the line.
pub(crate) fn clean(text: &str) -> String {
    text.chars()
        .filter(|&character| {
            !character.is_control()
                && !matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

/// The validation failure (exit 4) of a package or service name outside its grammar;
/// the name is not echoed and nothing is sent.
pub(crate) fn invalid_name() -> Failure {
    Failure::message(Exit::Validation, keys::CLI_ENTWARE_NAME_INVALID, &[])
}
