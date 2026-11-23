//! Todo 16: the refusals every Entware SSH command makes before it contacts the router or
//! the SSH server, each with its pinned exit code.

use kcc_app::audit::read_entries;
use kcc_i18n::keys;

use super::{
    lab::{CONFIRM, ROUTER, SshLab, refused, unconfirmed},
    support::{Run, TestResult},
};

/// A well-formed ticket: 64 lowercase hex digits.
const TICKET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A well-formed fingerprint, built at run time.
fn fingerprint() -> String {
    format!("SHA256:{}", "A".repeat(43))
}

/// Every command of todo 16, as the words after the global options.
fn commands() -> Vec<Vec<String>> {
    let fingerprint = fingerprint();
    let words = |text: &str| text.split(' ').map(str::to_owned).collect::<Vec<_>>();
    let mut all = [
        "entware ssh enable --port 2222",
        "entware ssh disable",
        "entware ssh probe",
        "entware ssh revoke",
        "entware packages list",
        "entware packages upgradable",
        "entware packages update",
        "entware packages install curl",
        "entware packages remove curl",
        "entware packages upgrade curl",
        "entware services list",
        "entware services status S51dropbear",
        "entware services start S51dropbear",
        "entware services stop S51dropbear",
        "entware services restart S51dropbear",
        "entware services log S51dropbear --lines 5",
    ]
    .map(words)
    .to_vec();
    for step in ["bootstrap", "repin"] {
        let mut command = words(&format!("entware ssh {step} --ticket {TICKET}"));
        command.extend(["--fingerprint".to_owned(), fingerprint.clone()]);
        all.push(command);
    }
    all
}

/// The audited CLI refusals with `outcome` on the lab router.
fn audited(lab: &SshLab, outcome: &str) -> TestResult<usize> {
    Ok(read_entries(&lab.base.env.state_dir())?
        .into_iter()
        .filter(|entry| {
            entry.action == "cli.refused"
                && entry.outcome == outcome
                && entry.router.as_deref() == Some(ROUTER)
        })
        .count())
}

/// Runs every command with `options` before it and checks `check`, that the refusal was
/// audited with `outcome`, and that neither the router nor the SSH server was contacted.
fn every_command(
    lab: &SshLab,
    (options, outcome): (&[&str], &str),
    check: impl Fn(&Run),
) -> TestResult {
    let before = lab.contacts();
    for command in commands() {
        let words = command.iter().map(String::as_str).collect::<Vec<_>>();
        let entries = audited(lab, outcome)?;

        let run = lab.run(&[options, &*words].concat())?;

        check(&run);
        assert_eq!(
            lab.contacts(),
            before,
            "kcc {options:?} {command:?} contacted a fake"
        );
        assert_eq!(
            Some(audited(lab, outcome)?),
            entries.checked_add(1),
            "{command:?} not audited"
        );
    }
    Ok(())
}

/// Todo 16: without `--confirm-destructive <router-id>`, with another router id, and with
/// `--yes` alone, every command exits 10 before any router request or SSH connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_or_wrong_confirmation_exits_10_without_contact() -> TestResult {
    let lab = SshLab::admin().await?;
    lab.enrol()?;
    for options in [
        &[][..],
        &["--confirm-destructive", "lab-2"][..],
        &["--yes"][..],
    ] {
        every_command(&lab, (options, "refused"), unconfirmed)?;
    }
    lab.shutdown().await
}

/// Todo 16: a viewer and an operator (no `Destructive`) are refused every command with
/// exit 10 before any router request or SSH connection, even when confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_and_operator_exit_10_without_contact() -> TestResult {
    let lab = SshLab::admin().await?;
    lab.enrol()?;
    for role in ["viewer", "operator"] {
        lab.role(role)?;
        every_command(&lab, (&CONFIRM, "forbidden"), |run| {
            refused(run, 10_i32, keys::CLI_REFUSED, &[("router", ROUTER)]);
        })?;
    }
    lab.shutdown().await
}

/// Todo 16: package and service names outside the grammar (space, newline, `;`, `../`,
/// upper case, very long) exit 4 before any router request or SSH connection, and the
/// name is not echoed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_names_exit_4_without_contact() -> TestResult {
    let lab = SshLab::admin().await?;
    lab.enrol()?;
    let before = lab.contacts();
    let long = "x".repeat(300);
    let packages = [
        "a b",
        "a\nb",
        "curl;reboot",
        "../curl",
        "Curl",
        "-x",
        long.as_str(),
    ];
    let long_service = format!("S51{long}");
    let services = [
        "S51drop bear",
        "S51drop\nbear",
        "S51dropbear;reboot",
        "../S51dropbear",
        "dropbear",
        long_service.as_str(),
    ];
    let mut runs = Vec::new();
    for verb in ["install", "remove", "upgrade"] {
        for name in packages {
            runs.push((["entware", "packages", verb, "--", name], name));
        }
    }
    for verb in ["status", "start", "stop", "restart", "log"] {
        for name in services {
            runs.push((["entware", "services", verb, "--", name], name));
        }
    }
    for (args, name) in runs {
        let run = lab.confirmed(&args)?;

        refused(&run, 4_i32, keys::CLI_ENTWARE_NAME_INVALID, &[]);
        if name.contains(';') {
            assert!(!run.stderr.contains(name), "name echoed: {run:?}");
        }
    }
    assert_eq!(lab.contacts(), before);
    lab.shutdown().await
}

/// Todo 16: a malformed ticket or fingerprint exits 4 before any contact, for bootstrap
/// and re-pin alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_ticket_or_fingerprint_exits_4_without_contact() -> TestResult {
    let lab = SshLab::admin().await?;
    drop(lab.enable()?);
    let before = lab.contacts();
    let good = fingerprint();
    let short = format!("SHA256:{}", "A".repeat(42));
    let long = format!("SHA256:{}", "A".repeat(44));
    let upper = TICKET.to_uppercase();
    let truncated = TICKET.chars().skip(1).collect::<String>();
    let cases = [
        (truncated.as_str(), good.as_str()),
        (upper.as_str(), good.as_str()),
        ("../ticket", good.as_str()),
        (TICKET, short.as_str()),
        (TICKET, "MD5:00:11"),
        (TICKET, long.as_str()),
    ];
    for step in ["bootstrap", "repin"] {
        for case in cases {
            let run = lab.step(step, case, &[])?;

            refused(&run, 4_i32, keys::CLI_ENTWARE_SSH_CONFIRMATION_INVALID, &[]);
        }
    }
    assert_eq!(lab.contacts(), before);
    lab.shutdown().await
}

/// Todo 16: the password is never taken from the command line: `--password` is no option
/// (exit 2, nothing contacted).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_password_on_the_command_line_is_refused() -> TestResult {
    let lab = SshLab::admin().await?;
    drop(lab.enable()?);
    let (ticket, fingerprint) = lab.probe()?;
    let before = lab.contacts();
    let password = lab.password.clone();
    let args = [
        "entware",
        "ssh",
        "bootstrap",
        "--ticket",
        &ticket,
        "--fingerprint",
        &fingerprint,
        "--password",
        &password,
    ];

    let run = lab.confirmed(&args)?;

    assert_eq!(run.code, 2_i32, "{run:?}");
    assert_eq!(lab.contacts(), before);
    lab.shutdown().await
}
