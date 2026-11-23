//! Todo 16: the probe and the bootstrap across two invocations, and the refusals of the
//! ticket that send no password.

use kcc_i18n::keys;
use kcc_testkit::entware_ssh::Config;
use serde_json::{Value, json};

use super::{
    lab::{CONFIRM, ROUTER, SshLab, en, refused},
    spawning,
    support::{self, TestResult},
};

/// The 64-hex-digit word of `text`, if any.
fn hex_word(text: &str) -> Option<&str> {
    text.split(|character: char| !character.is_ascii_hexdigit())
        .find(|word| word.len() == 64)
}

/// Todo 16: enable, a human probe and a JSON bootstrap enrol the router.
///
/// `ssh enable --port`, `ssh probe` (fingerprint, ticket and the out-of-band check) and
/// `ssh bootstrap` with `--password-file`: one password login installs kcc's marked key
/// line, one key login checks it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_and_bootstrap_with_a_password_file_enrol() -> TestResult {
    let lab = SshLab::admin().await?;
    let enabled = lab.enable()?;
    assert_eq!(
        enabled,
        json!({"router": ROUTER, "enabled": true, "port": lab.port, "state": "pending"})
    );
    let probe = lab.json(&["entware", "ssh", "probe"])?;
    let host_key = lab.ssh.host_key().to_openssh()?;
    assert_eq!(
        probe.get("host_key").and_then(Value::as_str),
        Some(host_key.trim())
    );
    let fingerprint = probe
        .get("fingerprint")
        .and_then(Value::as_str)
        .ok_or("no fingerprint")?
        .to_owned();
    assert!(fingerprint.starts_with("SHA256:"), "{probe}");
    assert!(
        probe.get("expires_at").and_then(Value::as_u64).is_some(),
        "{probe}"
    );

    let human = lab.confirmed(&["entware", "ssh", "probe"])?;
    assert_eq!(human.code, 0_i32, "{human:?}");
    let ticket = hex_word(&human.stdout)
        .ok_or("no ticket printed")?
        .to_owned();
    for text in [
        en(
            keys::CLI_ENTWARE_SSH_PROBE_KEY,
            &[("router", ROUTER), ("value", &fingerprint)],
        ),
        en(keys::CLI_ENTWARE_SSH_PROBE_TICKET, &[("item", &ticket)]),
        en(keys::CLI_ENTWARE_SSH_PROBE_CHECK, &[("router", ROUTER)]),
    ] {
        assert!(human.stdout.contains(&text), "{text:?}: {human:?}");
    }
    let before = lab.ssh.counters();

    let run = lab.step("bootstrap", (&ticket, &fingerprint), &["--json"])?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    let document: Value = serde_json::from_str(&run.stdout)?;
    assert_eq!(
        document,
        json!({"router": ROUTER, "enrolled": true, "fingerprint": fingerprint,
               "default_password_in_use": false})
    );
    let after = lab.ssh.counters();
    assert_eq!(after.password_attempts - before.password_attempts, 1);
    assert_eq!(after.key_offers - before.key_offers, 1);
    let lines = lab.ssh.authorized_keys();
    assert_eq!(
        lines
            .lines()
            .filter(|line| line.ends_with(" kcc:lab-1"))
            .count(),
        1
    );
    let listed = lab.json(&["entware", "packages", "list"])?;
    assert_eq!(listed, json!({"packages": []}));
    lab.shutdown().await
}

/// Todo 16: a well-formed but wrong fingerprint and a reused ticket are refused with exit
/// 10 and send no password; every attempt uses the ticket up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_fingerprints_and_reused_tickets_send_no_password() -> TestResult {
    let lab = SshLab::admin().await?;
    drop(lab.enable()?);
    let (ticket, fingerprint) = lab.probe()?;
    let wrong = format!("SHA256:{}", "B".repeat(43));
    let args = [("router", ROUTER)];

    let mismatch = lab.step("bootstrap", (&ticket, &wrong), &[])?;
    let reused = lab.step("bootstrap", (&ticket, &fingerprint), &[])?;

    refused(
        &mismatch,
        10_i32,
        keys::CLI_ENTWARE_SSH_TICKET_FINGERPRINT,
        &args,
    );
    refused(&reused, 10_i32, keys::CLI_ENTWARE_SSH_TICKET_MISSING, &args);
    assert_eq!(lab.ssh.counters().password_attempts, 0);
    assert_eq!(lab.ssh.counters().connections, 1, "the probe only");

    let (fresh, confirmed) = lab.probe()?;
    let enrolled = lab.step("bootstrap", (&fresh, &confirmed), &[])?;
    assert_eq!(enrolled.code, 0_i32, "{enrolled:?}");
    let again = lab.step("bootstrap", (&fresh, &confirmed), &["--yes"])?;
    refused(&again, 10_i32, keys::CLI_ENTWARE_SSH_TICKET_MISSING, &args);
    let repin = lab.step("repin", (&fresh, &confirmed), &["--yes"])?;
    refused(&repin, 10_i32, keys::CLI_ENTWARE_SSH_TICKET_MISSING, &args);
    assert_eq!(lab.ssh.counters().password_attempts, 1);
    lab.shutdown().await
}

/// Todo 16: a bootstrap or re-pin of an Active enrolment prints the notice that the local
/// key is replaced first and needs `--yes`; without it nothing is contacted and the
/// enrolment keeps working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_active_enrolment_needs_yes_for_a_new_bootstrap() -> TestResult {
    let lab = SshLab::admin().await?;
    lab.enrol()?;
    let (ticket, fingerprint) = lab.probe()?;
    let notice = en(keys::CLI_ENTWARE_SSH_ACTIVE_NOTICE, &[("router", ROUTER)]);
    let before = lab.contacts();
    for step in ["bootstrap", "repin"] {
        let run = lab.step(step, (&ticket, &fingerprint), &[])?;

        refused(
            &run,
            10_i32,
            keys::CLI_CONFIRM_MISSING,
            &[("router", ROUTER)],
        );
        assert!(run.stderr.contains(&notice), "{run:?}");
        assert_eq!(lab.contacts(), before, "{step}");
    }
    let listed = lab.json(&["entware", "packages", "list"])?;
    assert_eq!(listed, json!({"packages": []}));

    let confirmed = lab.step("bootstrap", (&ticket, &fingerprint), &["--yes"])?;

    assert_eq!(confirmed.code, 0_i32, "{confirmed:?}");
    assert!(confirmed.stderr.contains(&notice), "{confirmed:?}");
    lab.shutdown().await
}

/// Todo 16: without `--password-file` the password comes from `KCC_PASSWORD`; the
/// default password is reported (without the password itself).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_password_may_come_from_kcc_password() -> TestResult {
    let lab = SshLab::spawn("admin", Config::default()).await?;
    drop(lab.enable()?);
    let (ticket, fingerprint) = lab.probe()?;
    let config = lab.base.env.path("kcc.toml");
    let args = [
        &["--config", config.to_str().ok_or("non-UTF-8 path")?][..],
        &CONFIRM[..],
        &[
            "entware",
            "ssh",
            "bootstrap",
            "--ticket",
            &ticket,
            "--fingerprint",
            &fingerprint,
        ],
    ]
    .concat();
    let mut command = lab.base.env.command(&args);
    let _: &mut _ = command.env("KCC_PASSWORD", &lab.password);

    let run = support::finish(spawning::spawn(&mut command)?)?;

    lab.assert_clean(&run);
    assert_eq!(run.code, 0_i32, "{run:?}");
    let enrolled = en(
        keys::CLI_ENTWARE_SSH_ENROLLED,
        &[("router", ROUTER), ("value", &fingerprint)],
    );
    assert!(run.stdout.contains(&enrolled), "{run:?}");
    let default = en(
        keys::CLI_ENTWARE_SSH_DEFAULT_PASSWORD,
        &[("router", ROUTER)],
    );
    assert!(!run.stderr.contains(&default), "{run:?}");
    lab.shutdown().await
}

/// Todo 16: a wrong password is an authentication failure (exit 3) after exactly one
/// password attempt, and neither password is printed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_exits_3() -> TestResult {
    let lab = SshLab::admin().await?;
    drop(lab.enable()?);
    let (ticket, fingerprint) = lab.probe()?;
    let wrong = format!("wrong-{}", super::lab::marker());
    drop(lab.base.env.write("entware.password", &wrong)?);

    let run = lab.step("bootstrap", (&ticket, &fingerprint), &[])?;

    refused(
        &run,
        3_i32,
        keys::CLI_ENTWARE_SSH_AUTH_REJECTED,
        &[("router", ROUTER)],
    );
    assert!(
        !run.stdout.contains(&wrong) && !run.stderr.contains(&wrong),
        "{run:?}"
    );
    assert_eq!(lab.ssh.counters().password_attempts, 1);
    lab.shutdown().await
}
