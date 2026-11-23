//! `kcc entware ssh`: switching SSH management on, the probe and the bootstrap or re-pin
//! across two invocations, revoke and disable.

use kcc_app::entware_ssh::state::{self, EnrolmentState, SshStore};
use kcc_catalog::Risk;
use kcc_domain::entware::ssh::enrol::{self, Confirmation};
use kcc_i18n::keys;
use serde_json::json;

use super::{
    args_dom_entware_ssh::{ConfirmedProbe, EntwareSshCommand},
    context::Ctx,
    dom_entware_ssh_gate::open,
    entry::Boxed,
    exit::{Exit, Failure, Outcome},
    secret::{confirm, read_secret},
};

/// The hexadecimal digits of a probe ticket.
const TICKET_DIGITS: usize = 64;

/// The base64 characters of an ed25519 SHA-256 fingerprint after `SHA256:`.
const FINGERPRINT_CHARS: usize = 43;

/// Runs an `entware ssh` command.
///
/// The returned future fails with the command's failure and its exit code; see [`Boxed`]
/// for why it is boxed.
// NOT cancel-safe: enrolment steps change the router and local state.
pub(crate) fn ssh(ctx: &Ctx, command: EntwareSshCommand) -> Boxed<'_> {
    match command {
        EntwareSshCommand::Enable { port } => Box::pin(enable(ctx, port)),
        EntwareSshCommand::Disable => Box::pin(disable(ctx)),
        EntwareSshCommand::Probe => Box::pin(probe(ctx)),
        EntwareSshCommand::Bootstrap(probe) => Box::pin(enrolment(ctx, probe, false)),
        EntwareSshCommand::Repin(probe) => Box::pin(enrolment(ctx, probe, true)),
        EntwareSshCommand::Revoke => Box::pin(revoke(ctx)),
    }
}

/// Switches SSH management on, on `port` when given; contacts nothing.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: writes local state.
async fn enable(ctx: &Ctx, port: Option<u16>) -> Outcome {
    let opened = open(ctx).await?;
    let (ssh, caller, out) = (opened.ssh(), opened.caller(), ctx.out());
    let enabled = enrol::set_enabled(&ssh, &caller, true)
        .await
        .map_err(|error| opened.failure(out, error))?;
    let record = match port {
        Some(chosen) => enrol::set_port(&ssh, &caller, chosen)
            .await
            .map_err(|error| opened.failure(out, error))?,
        None => enabled,
    };
    let state = match record.state {
        EnrolmentState::Active => "active",
        EnrolmentState::Pending | _ => "pending",
    };
    let shown_port = record.port.to_string();
    out.emit(
        &json!({
            "router": opened.id(),
            "enabled": record.enabled,
            "port": record.port,
            "state": state,
        }),
        &out.tr(
            keys::CLI_ENTWARE_SSH_ENABLED,
            &[("router", opened.id()), ("port", &shown_port)],
        ),
    )
}

/// Forgets kcc's key and pin locally; contacts nothing.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: writes local state and the audit log.
async fn disable(ctx: &Ctx) -> Outcome {
    let opened = open(ctx).await?;
    let out = ctx.out();
    let disabled = enrol::disable(&opened.ssh(), &opened.caller())
        .await
        .map_err(|error| opened.failure(out, error))?;
    out.emit(
        &json!({
            "router": opened.id(),
            "disabled": true,
            "entware_key_still_authorized": disabled.entware_key_still_authorized,
        }),
        &out.tr(keys::CLI_ENTWARE_SSH_FORGOTTEN, &[("router", opened.id())]),
    )
}

/// Probes the host key and prints its fingerprint, the ticket and how to check the
/// fingerprint out of band.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the router read may sign in first; the audit entry may append after
// cancellation.
async fn probe(ctx: &Ctx) -> Outcome {
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let out = ctx.out();
    let ticket = enrol::probe(&opened.ssh(), target.router(), &opened.caller())
        .await
        .map_err(|error| opened.failure(out, error))?;
    let router = opened.id();
    let human = [
        out.tr(
            keys::CLI_ENTWARE_SSH_PROBE_KEY,
            &[("router", router), ("value", &ticket.fingerprint)],
        ),
        out.tr(
            keys::CLI_ENTWARE_SSH_PROBE_TICKET,
            &[("item", &ticket.nonce)],
        ),
        out.tr(keys::CLI_ENTWARE_SSH_PROBE_CHECK, &[("router", router)]),
    ]
    .join("\n");
    out.emit(
        &json!({
            "router": router,
            "fingerprint": ticket.fingerprint,
            "host_key": ticket.host_key,
            "ticket": ticket.nonce,
            "expires_at": ticket.expires_at,
        }),
        &human,
    )
}

/// Bootstraps (or, with `repin`, re-pins) with the confirmed `probe` and the Entware
/// root password.
///
/// The ticket and fingerprint are checked first; then the destructive gate; an Active
/// enrolment needs `--yes` after its notice; the password is read before the router is
/// contacted.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: dropped mid-way, the enrolment stays Pending.
async fn enrolment(ctx: &Ctx, probe: ConfirmedProbe, repin: bool) -> Outcome {
    let (nonce, fingerprint) = confirmed_probe(probe)?;
    let opened = open(ctx).await?;
    let out = ctx.out();
    let router = opened.id();
    let store = SshStore::new(ctx.state().clone(), opened.services().key().duplicate());
    if state::active(&store, router) {
        out.note(&out.tr(keys::CLI_ENTWARE_SSH_ACTIVE_NOTICE, &[("router", router)]));
        let confirmation = confirm(out, ctx.globals(), Risk::Management, router, false);
        ctx.confirmed(opened.services(), router, confirmation)
            .await?;
    }
    let prompt = out.tr(keys::CLI_PROMPT_ENTWARE_PASSWORD, &[("router", router)]);
    let password = read_secret(ctx.globals().password_file(), &prompt)?;
    let target = opened.target(ctx).await?;
    let (ssh, caller) = (opened.ssh(), opened.caller());
    let confirmation = Confirmation::new(nonce, fingerprint, password);
    let enrolled = if repin {
        enrol::repin(&ssh, target.router(), &caller, confirmation).await
    } else {
        enrol::bootstrap(&ssh, target.router(), &caller, confirmation).await
    }
    .map_err(|error| opened.failure(out, error))?;
    if enrolled.default_password_in_use {
        out.note(&out.tr(
            keys::CLI_ENTWARE_SSH_DEFAULT_PASSWORD,
            &[("router", router)],
        ));
    }
    out.emit(
        &json!({
            "router": router,
            "enrolled": true,
            "fingerprint": enrolled.fingerprint,
            "default_password_in_use": enrolled.default_password_in_use,
        }),
        &out.tr(
            keys::CLI_ENTWARE_SSH_ENROLLED,
            &[("router", router), ("value", &enrolled.fingerprint)],
        ),
    )
}

/// Removes kcc's key line from the router, then the local state.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: dropped after the removal, the local state stays.
async fn revoke(ctx: &Ctx) -> Outcome {
    let opened = open(ctx).await?;
    let target = opened.target(ctx).await?;
    let out = ctx.out();
    enrol::revoke(&opened.ssh(), target.router(), &opened.caller())
        .await
        .map_err(|error| opened.failure(out, error))?;
    out.emit(
        &json!({ "router": opened.id(), "revoked": true }),
        &out.tr(keys::CLI_ENTWARE_SSH_REVOKED, &[("router", opened.id())]),
    )
}

/// The ticket (64 lowercase hex digits) and the fingerprint (`SHA256:` and 43 base64
/// characters) of `probe`.
///
/// # Errors
///
/// Returns the validation failure (exit 4) for any other value; nothing is sent.
fn confirmed_probe(probe: ConfirmedProbe) -> Outcome<(String, String)> {
    let ticket = probe.ticket.len() == TICKET_DIGITS
        && probe
            .ticket
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let fingerprint = probe
        .fingerprint
        .strip_prefix("SHA256:")
        .is_some_and(|hash| {
            hash.len() == FINGERPRINT_CHARS
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
        });
    if ticket && fingerprint {
        Ok((probe.ticket, probe.fingerprint))
    } else {
        Err(Failure::message(
            Exit::Validation,
            keys::CLI_ENTWARE_SSH_CONFIRMATION_INVALID,
            &[],
        ))
    }
}
