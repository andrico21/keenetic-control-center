//! `kcc entware set ...` and `kcc entware remove`: the confirmation each risk needs, the
//! warnings, the management bracket and the result document.

use kcc_i18n::keys;
use serde_json::{Value, json};

use super::{
    lab::{ARM, DISARM, Lab, en, unconfirmed},
    support::TestResult,
};

/// The initrc path the tests set.
const INITRC: &str = "/opt/etc/init.d/rc.unslung";

/// Todo 13: enabling chroot prints the SSH warning and applies `opkg chroot`; the JSON
/// document carries the applied flags and the warning names, and disabling warns nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chroot_warns_about_ssh_when_enabled_and_applies() -> TestResult {
    let lab = Lab::spawn("operator").await?;
    let warning = en(keys::CLI_ENTWARE_WARNING_CHROOT, &[]);

    let on = lab.run(&["entware", "set", "chroot", "on"])?;
    assert_eq!(on.code, 0_i32, "{on:?}");
    assert!(on.stderr.contains(&warning), "{on:?}");
    assert!(lab.fake.running_config_text().contains("opkg chroot"));

    let off = lab.json(&["entware", "set", "chroot", "off"])?;
    assert_eq!(
        off,
        json!({"applied": true, "unsaved": true, "persists_immediately": false, "warnings": []})
    );
    assert!(!lab.fake.running_config_text().contains("opkg chroot"));

    let again = lab.json(&["entware", "set", "chroot", "on"])?;
    assert_eq!(
        again.get("warnings"),
        Some(&json!(["chroot_stops_ssh_management"])),
        "{again}"
    );
    let quiet = lab.run(&["entware", "set", "chroot", "off"])?;
    assert!(!quiet.stderr.contains(&warning), "{quiet:?}");
    lab.shutdown().await
}

/// Todo 13: the timezone takes `auto` or a name, as the operator's ordinary write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timezone_takes_auto_or_a_name() -> TestResult {
    let lab = Lab::spawn("operator").await?;

    drop(lab.json(&["entware", "set", "timezone", "Europe/Berlin"])?);
    let named = lab.commands();
    drop(lab.json(&["entware", "set", "timezone", "auto"])?);
    let auto = lab.commands();

    assert!(
        named
            .iter()
            .any(|line| line == "opkg timezone Europe/Berlin"),
        "{named:?}"
    );
    assert!(
        auto.iter().any(|line| line == "opkg timezone auto"),
        "{auto:?}"
    );
    let invalid = lab.run(&["entware", "set", "timezone", "../x"])?;
    assert_eq!(invalid.code, 4_i32, "{invalid:?}");
    assert_eq!(lab.commands(), auto, "nothing sent for an invalid name");
    lab.shutdown().await
}

/// Todo 13: the initrc path is destructive: without `--confirm-destructive` or with
/// another router id it is refused (exit 10) and never sent; an invalid path is exit 4.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initrc_needs_the_router_id() -> TestResult {
    let lab = Lab::spawn("admin").await?;
    let line = format!("opkg initrc {INITRC}");

    for confirm in [&[][..], &["--confirm-destructive", "prod-1"]] {
        let run = lab.run(&[confirm, &["entware", "set", "initrc", INITRC]].concat())?;
        assert_eq!(run.code, 10_i32, "{confirm:?}: {run:?}");
        assert!(run.stderr.contains(&unconfirmed()), "{run:?}");
    }
    let invalid = lab.run(&[
        "--confirm-destructive",
        "lab-1",
        "entware",
        "set",
        "initrc",
        "/etc/passwd",
    ])?;
    assert_eq!(invalid.code, 4_i32, "{invalid:?}");
    assert_eq!(lab.commands(), Vec::<String>::new());

    let done = lab.json(&[
        "--confirm-destructive",
        "lab-1",
        "entware",
        "set",
        "initrc",
        INITRC,
    ])?;
    assert_eq!(done.get("applied"), Some(&Value::Bool(true)), "{done}");
    assert_eq!(lab.commands(), [line]);
    lab.shutdown().await
}

/// Todo 13: dns-override is a management change: without `--yes` it is refused (exit 10)
/// and nothing is sent; with it the fail-safe timer is armed before the line and disarmed
/// after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_override_needs_yes_and_runs_inside_the_bracket() -> TestResult {
    let lab = Lab::spawn("admin").await?;

    let refused = lab.run(&["entware", "set", "dns-override", "on"])?;
    assert_eq!(refused.code, 10_i32, "{refused:?}");
    assert!(refused.stderr.contains(&unconfirmed()), "{refused:?}");
    assert_eq!(lab.commands(), Vec::<String>::new());

    let done = lab.json(&["--yes", "entware", "set", "dns-override", "on"])?;

    assert_eq!(
        done.get("warnings"),
        Some(&json!(["dns_override_stops_router_dns"])),
        "{done}"
    );
    let commands = lab.commands();
    let line = commands
        .iter()
        .position(|command| command == "opkg dns-override")
        .ok_or("no dns-override line")?;
    assert_eq!(
        commands.first().map(String::as_str),
        Some(ARM),
        "{commands:?}"
    );
    assert_eq!(
        commands.last().map(String::as_str),
        Some(DISARM),
        "{commands:?}"
    );
    assert!(line > 0 && line + 1 < commands.len(), "{commands:?}");
    assert!(!lab.fake.recovery_armed(), "timer disarmed");
    lab.shutdown().await
}

/// Todo 13: removal is destructive: refused without the router id or with another one,
/// applied with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remove_needs_the_router_id() -> TestResult {
    let lab = Lab::spawn("admin").await?;
    assert!(lab.fake.configure("opkg disk fixture-media:/"));

    for confirm in [&[][..], &["--confirm-destructive", "prod-1"]] {
        let run = lab.run(&[confirm, &["entware", "remove"]].concat())?;
        assert_eq!(run.code, 10_i32, "{confirm:?}: {run:?}");
        assert!(run.stderr.contains(&unconfirmed()), "{run:?}");
    }
    assert_eq!(lab.commands(), Vec::<String>::new());

    let done = lab.json(&["--confirm-destructive", "lab-1", "entware", "remove"])?;

    assert_eq!(done.get("applied"), Some(&Value::Bool(true)), "{done}");
    assert_eq!(lab.commands(), ["no opkg disk"]);
    assert!(!lab.fake.running_config_text().contains("opkg disk"));
    lab.shutdown().await
}
