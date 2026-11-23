//! What the Entware page says about a refused or failed SSH flow: one localized sentence
//! and its audit code, and for a changed host key both fingerprints.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_app::{entware_ssh::SshStateError, jobs::JobError, workflow::WorkflowError};
use kcc_domain::entware::ssh::error::EntwareError;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_ssh::error::SshError;

use crate::{
    markup::Rendered,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, outcome::Failure, request::rendered},
};

/// The banner of a host key that differs from the pinned one.
#[derive(Template)]
#[template(path = "partials/system_entware_ssh_mismatch.html")]
struct Mismatch {
    /// Locale carrier.
    shell: Shell,
    /// The pinned fingerprint.
    pinned: String,
    /// The fingerprint the router presented.
    presented: String,
}

localized!(Mismatch);

/// The sentence and audit code of `error` in `locale`, and the mismatch banner when the
/// router presented another host key than the pinned one.
pub(super) fn answer_to(error: &EntwareError, locale: Locale) -> (Failure, Option<Rendered>) {
    let said = |key: MessageKey, audit| Failure::new(tr(locale, key, None), audit);
    let named = |key: MessageKey, name: &str, audit| {
        let mut args = FluentArgs::new();
        args.set("name", name.to_owned());
        Failure::new(tr(locale, key, Some(&args)), audit)
    };
    let failure = match error {
        EntwareError::PermissionDenied => Failure::forbidden(locale),
        EntwareError::McpRefused => said(keys::WEB_SYSTEM_ENTWARE_SSH_MCP_REFUSED, "refused"),
        EntwareError::ChrootEnabled => said(keys::WEB_SYSTEM_ENTWARE_SSH_CHROOT, "refused"),
        EntwareError::RouterHostChanged => {
            said(keys::WEB_SYSTEM_ENTWARE_SSH_HOST_CHANGED, "refused")
        }
        EntwareError::NotEnrolled => said(keys::WEB_SYSTEM_ENTWARE_SSH_NOT_ENROLLED, "refused"),
        EntwareError::RepinRequired => said(keys::WEB_SYSTEM_ENTWARE_SSH_REPIN_REQUIRED, "refused"),
        EntwareError::HostKeyUnchanged => {
            said(keys::WEB_SYSTEM_ENTWARE_SSH_HOST_KEY_UNCHANGED, "refused")
        }
        EntwareError::Workflow(WorkflowError::RouterBusy { actor: _ })
        | EntwareError::Job(JobError::RouterBusy { router: _ }) => {
            said(keys::WEB_SYSTEM_JOB_BUSY, "busy")
        }
        EntwareError::Workflow(WorkflowError::VerificationFailed { field: _ }) => {
            said(keys::WEB_SYSTEM_ENTWARE_SSH_VERIFICATION, "failed")
        }
        EntwareError::Domain(_) => said(keys::WEB_SYSTEM_ENTWARE_SSH_UNREACHABLE, "failed"),
        EntwareError::State(SshStateError::Ticket(_)) => {
            said(keys::WEB_SYSTEM_ENTWARE_SSH_TICKET_INVALID, "refused")
        }
        EntwareError::State(SshStateError::InvalidPort) => {
            said(keys::WEB_SYSTEM_ENTWARE_SSH_PORT_RULE, "validation_failed")
        }
        EntwareError::State(_) => said(keys::WEB_SYSTEM_ENTWARE_SSH_STATE_FAILED, "failed"),
        EntwareError::Ssh(SshError::HostKeyMismatch {
            expected: _,
            actual: _,
        }) => said(keys::WEB_SYSTEM_ENTWARE_SSH_MISMATCH, "refused"),
        EntwareError::Ssh(SshError::AuthRejected) => {
            said(keys::WEB_SYSTEM_ENTWARE_SSH_AUTH_REJECTED, "refused")
        }
        EntwareError::Ssh(SshError::NotAdmitted) => {
            said(keys::WEB_SYSTEM_ENTWARE_SSH_NOT_ADMITTED, "refused")
        }
        EntwareError::RevokeFailed(_) | EntwareError::RevokeUnreachable(_) => {
            said(keys::WEB_SYSTEM_ENTWARE_SSH_REVOKE_FAILED, "failed")
        }
        EntwareError::Audit(_) => said(keys::WEB_SYSTEM_ENTWARE_SSH_AUDIT, "failed"),
        EntwareError::SshDisabled => said(keys::WEB_SYSTEM_ENTWARE_SSH_SWITCHED_OFF, "refused"),
        EntwareError::PackageNotInstalled { package } => named(
            keys::WEB_SYSTEM_ENTWARE_SSH_PACKAGE_MISSING,
            package,
            "refused",
        ),
        EntwareError::UnknownService { service } => named(
            keys::WEB_SYSTEM_ENTWARE_SSH_SERVICE_UNKNOWN,
            service,
            "refused",
        ),
        EntwareError::ServiceDisabled { service, state: _ } => named(
            keys::WEB_SYSTEM_ENTWARE_SSH_SERVICE_DISABLED,
            service,
            "refused",
        ),
        EntwareError::Ssh(_) | EntwareError::Workflow(_) | EntwareError::Job(_) | _ => {
            tracing::warn!(%error, "Entware SSH action failed");
            let key = if matches!(error, EntwareError::Ssh(_)) {
                keys::WEB_SYSTEM_ENTWARE_SSH_SSH_FAILED
            } else {
                keys::WEB_SYSTEM_ENTWARE_SSH_FAILED
            };
            said(key, "failed")
        }
    };
    (failure, mismatch(error, locale))
}

/// The banner naming both fingerprints of a host key mismatch.
fn mismatch(error: &EntwareError, locale: Locale) -> Option<Rendered> {
    let (EntwareError::Ssh(SshError::HostKeyMismatch { expected, actual })
    | EntwareError::RevokeFailed(SshError::HostKeyMismatch { expected, actual })) = error
    else {
        return None;
    };
    rendered(&Mismatch {
        shell: fragment_shell(locale),
        pinned: expected.clone(),
        presented: actual.clone(),
    })
}
