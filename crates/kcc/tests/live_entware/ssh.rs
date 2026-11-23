//! The SSH suite: enrol kcc's key on a test router's Entware, exercise the package and
//! service commands, and always revoke the key again.

use core::cell::RefCell;

use serde_json::{Map, Value, json};

use super::{
    Reach, TestResult,
    admit::{Home, ROUTER, admit},
    cleanup::{Cleanup, RevokeFailed, always_revoke, manual},
    contract::{self, Read, SshEnv, skip},
    evidence,
};

/// Where the enrolment script keeps kcc's key line on the router.
const AUTHORIZED_KEYS: &str = "/opt/etc/dropbear/authorized_keys";

/// The tools the enrolment script runs; a passing bootstrap proves them present.
const SCRIPT_TOOLS: [&str; 6] = ["grep", "mv", "chmod", "touch", "mkdir", "printf"];

/// The suite's record, filled step by step.
type Record = RefCell<Map<String, Value>>;

/// Runs the SSH suite: the gate, the port probe, then the guarded steps and the revoke.
// NOT cancel-safe: dropping it after the bootstrap skips the revoke.
pub(crate) async fn run(read: Read<'_>, reach: &Reach) -> TestResult {
    let env = match contract::ssh(read) {
        Ok(env) => env,
        Err(reason) => {
            skip(reason);
            return Ok(());
        }
    };
    let admitted = admit(&env.base, reach.allow_loopback).await?;
    let home = admitted.home;
    let record = Record::default();
    let probed = probe(&home, &reach.ssh_ports, &record);
    let outcome = match probed {
        Ok(confirmation) => always_revoke(
            || steps(&home, &env, &confirmation, &record),
            || revoke(&home, &record),
        ),
        Err(error) => Err(Cleanup::Steps(error)),
    };
    drop(evidence::write(
        &reach.evidence,
        evidence::SSH,
        &Value::Object(record.into_inner()),
    )?);
    match outcome {
        Ok(()) => Ok(()),
        Err(Cleanup::Steps(error)) => Err(error),
        Err(Cleanup::Revoke {
            steps: earlier,
            revoke: error,
        }) => {
            let failed = earlier.map(|failure| failure.to_string());
            let kept = home.keep();
            Err(RevokeFailed {
                manual: manual(ROUTER, &kept, (failed.as_deref(), &error.to_string())),
            }
            .into())
        }
    }
}

/// Sets `name` in the record.
fn note(record: &Record, name: &str, value: Value) {
    drop(record.borrow_mut().insert(name.to_owned(), value));
}

/// A string member of a `kcc` JSON document.
fn text(document: &Value, name: &str) -> TestResult<String> {
    Ok(document
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no {name} in {document}"))?
        .to_owned())
}

/// Enables SSH on the first port whose probe answers; returns the ticket and fingerprint.
fn probe(home: &Home, ports: &[u16], record: &Record) -> TestResult<(String, String)> {
    let mut failures = Vec::new();
    for port in ports {
        let port_text = port.to_string();
        drop(home.json(&["entware", "ssh", "enable", "--port", &port_text])?);
        match home.json(&["entware", "ssh", "probe"]) {
            Ok(probe) => {
                note(record, "port", json!(port));
                note(record, "probe_failures", json!(failures));
                return Ok((text(&probe, "ticket")?, text(&probe, "fingerprint")?));
            }
            Err(error) => failures.push(json!({"port": port, "error": error.to_string()})),
        }
    }
    note(record, "probe_failures", json!(failures));
    Err(format!("no Entware SSH server answered on ports {ports:?}").into())
}

/// The guarded steps: bootstrap, packages, services.
fn steps(
    home: &Home,
    env: &SshEnv,
    (ticket, fingerprint): &(String, String),
    record: &Record,
) -> TestResult {
    let file = env
        .entware_password_file
        .to_str()
        .ok_or("KCC_LIVE_ENTWARE_PASSWORD_FILE is not UTF-8")?;
    let boot = home.kcc(&[
        "--password-file",
        file,
        "entware",
        "ssh",
        "bootstrap",
        "--ticket",
        ticket,
        "--fingerprint",
        fingerprint,
    ])?;
    note(record, "authorized_keys", json!(AUTHORIZED_KEYS));
    note(record, "bootstrap_exit", json!(boot.code));
    if boot.code != 0_i32 {
        return Err(format!(
            "bootstrap exited {} (the enrolment script needs {}): {}",
            boot.code,
            SCRIPT_TOOLS.join(", "),
            boot.stderr.trim()
        )
        .into());
    }
    let enrolled: Value = serde_json::from_str(&boot.stdout)?;
    note(record, "script_tools_present", json!(SCRIPT_TOOLS));
    note(
        record,
        "default_password_in_use",
        json!(enrolled.get("default_password_in_use")),
    );
    packages(home, &env.package, record)?;
    services(home, record)
}

/// Lists the packages, then installs and removes `package`, which must be absent before.
fn packages(home: &Home, package: &str, record: &Record) -> TestResult {
    let listed = home.json(&["entware", "packages", "list"])?;
    let names = listed
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("no packages in the list")?
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    note(record, "packages_installed", json!(names.len()));
    if names.contains(&package) {
        return Err(format!(
            "{package} is already installed; the suite removes only what it installed"
        )
        .into());
    }
    let installed = home.json(&["entware", "packages", "install", package])?;
    note(record, "install", installed.clone());
    if installed.get("after").is_none_or(Value::is_null) {
        return Err(format!("{package} is not installed after the install").into());
    }
    let removed = home.json(&["entware", "packages", "remove", package])?;
    note(record, "remove", removed.clone());
    if !removed.get("after").is_some_and(Value::is_null) {
        return Err(format!("{package} is still installed after the remove").into());
    }
    Ok(())
}

/// Lists the services and checks the first one.
fn services(home: &Home, record: &Record) -> TestResult {
    let listed = home.json(&["entware", "services", "list"])?;
    let names = listed
        .get("services")
        .and_then(Value::as_array)
        .ok_or("no services in the list")?;
    note(record, "services", json!(names.len()));
    let Some(first) = names.first().and_then(Value::as_str) else {
        note(record, "service", Value::Null);
        return Ok(());
    };
    let status = home.json(&["entware", "services", "status", first])?;
    note(record, "service", status);
    Ok(())
}

/// Revokes kcc's key; the record says whether it worked.
fn revoke(home: &Home, record: &Record) -> TestResult {
    let outcome = home
        .json(&["entware", "ssh", "revoke"])
        .and_then(|revoked| {
            if revoked.get("revoked") == Some(&Value::Bool(true)) {
                Ok(())
            } else {
                Err(format!("unexpected revoke reply {revoked}").into())
            }
        });
    note(record, "revoked", json!(outcome.is_ok()));
    outcome
}
