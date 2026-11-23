//! Todo 16: the ticket refusals of the bootstrap and the re-pin that send nothing over
//! SSH: an expired ticket, another actor, another nonce and another SSH port.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    accounts::Clock,
    entware_ssh::ticket::{TicketScope, TicketStore},
    persist::StateStore,
    secrets::MasterKey,
};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    lab::{CONFIRM, ROUTER, SshLab, refused},
    spawning,
    support::{self, Run, TestResult, USER},
};

/// A clock stuck long before any ticket of a test could still be valid.
#[derive(Debug)]
struct Past;

impl Clock for Past {
    fn unix_seconds(&self) -> u64 {
        1_000
    }
}

/// How a sub-case spoils the probe's ticket before the step runs.
#[derive(Clone, Copy, Debug)]
enum Spoil {
    /// The router's ticket is replaced by one issued long ago.
    Expired,
    /// Another operating-system user redeems it.
    Actor,
    /// A well-formed nonce that was never issued is presented.
    Nonce,
    /// The router's SSH port changes between the probe and the step.
    Port,
}

/// Runs `kcc entware ssh <step>` with the password file as the operating-system user
/// `user`.
fn step_as(lab: &SshLab, user: &str, step: &str, ticket: (&str, &str)) -> TestResult<Run> {
    let config = lab.base.env.path("kcc.toml");
    let file = lab.password_file.to_str().ok_or("non-UTF-8 path")?;
    let args = [
        &["--config", config.to_str().ok_or("non-UTF-8 path")?][..],
        &CONFIRM[..],
        &["--password-file", file],
        &["entware", "ssh", step, "--ticket", ticket.0],
        &["--fingerprint", ticket.1],
    ]
    .concat();
    let mut command = lab.base.env.command(&args);
    let _: &mut _ = command.env("USER", user);
    let run = support::finish(spawning::spawn(&mut command)?)?;
    lab.assert_clean(&run);
    Ok(run)
}

/// Runs `step` with the probed `ticket` spoiled by `spoil`, and returns the run and the
/// message key it must carry.
fn spoiled(
    lab: &SshLab,
    spoil: Spoil,
    step: &str,
    (nonce, fingerprint): (&str, &str),
) -> TestResult<(Run, MessageKey)> {
    let invalid = keys::CLI_ENTWARE_SSH_TICKET_INVALID;
    Ok(match spoil {
        Spoil::Expired => {
            let host_key = lab.ssh.host_key().to_openssh()?;
            let store = TicketStore::new(
                StateStore::open(&lab.base.env.state_dir())?,
                MasterKey::from_bytes([17_u8; 32]),
                Arc::new(Past),
            );
            let actor = format!("cli:{USER}");
            let scope = TicketScope::new(ROUTER, lab.port, &actor);
            let old = store.issue(scope, host_key.trim(), fingerprint)?;
            let run = lab.step(step, (&old, fingerprint), &[])?;
            (run, keys::CLI_ENTWARE_SSH_TICKET_EXPIRED)
        }
        Spoil::Actor => (
            step_as(lab, "mallory", step, (nonce, fingerprint))?,
            invalid,
        ),
        Spoil::Nonce => (
            lab.step(step, (&"f".repeat(64), fingerprint), &[])?,
            invalid,
        ),
        Spoil::Port => {
            let other = if lab.port == 2222 { "2223" } else { "2222" };
            drop(lab.json(&["entware", "ssh", "enable", "--port", other])?);
            let run = lab.step(step, (nonce, fingerprint), &[]);
            drop(lab.enable()?);
            (run?, invalid)
        }
    })
}

/// Todo 16: spoiled tickets exit 10 before any SSH connection, so no password is sent.
///
/// An expired ticket exits with `ticket-expired`; a ticket of another actor, another
/// nonce or another SSH port exits with `ticket-invalid`; for the bootstrap and for the
/// re-pin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spoiled_tickets_exit_10_without_ssh_contact() -> TestResult {
    let lab = SshLab::admin().await?;
    drop(lab.enable()?);

    for step in ["bootstrap", "repin"] {
        for spoil in [Spoil::Expired, Spoil::Actor, Spoil::Nonce, Spoil::Port] {
            let (ticket, fingerprint) = lab.probe()?;
            let probed = lab.ssh.counters();

            let (run, key) = spoiled(&lab, spoil, step, (&ticket, &fingerprint))?;

            refused(&run, 10_i32, key, &[("router", ROUTER)]);
            assert_eq!(lab.ssh.counters(), probed, "{step} {spoil:?}: SSH contact");
        }
    }
    assert_eq!(lab.ssh.counters().password_attempts, 0);
    lab.shutdown().await
}
