//! The guided setup suite: on an eligible spare drive of a test router, `kcc entware setup`
//! runs to its end and the installer's log lines are recorded. It never saves.

use core::{error::Error, fmt};

use kcc_rci::{RciBody, RciPath};
use serde_json::{Value, json};

use super::{
    Reach, TestResult,
    admit::admit,
    contract::{self, Read, skip},
    evidence,
};

/// Log lines read back after the setup.
const LOG_LINES: u32 = 500;

/// The component tag of the installer's log lines.
const INSTALLER: &str = "Opkg::Manager";

/// Why the setup suite refuses a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupRefusal {
    /// `KCC_LIVE_ENTWARE_DRIVE` is not one of the drives `kcc entware status` lists.
    DriveNotEligible,
}

impl fmt::Display for SetupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KCC_LIVE_ENTWARE_DRIVE is not an eligible drive of the router")
    }
}

impl Error for SetupRefusal {}

/// Runs the setup suite: the gate, the eligibility check, the setup, the record.
// NOT cancel-safe: dropping it mid-way can leave the setup job running in the kcc child.
pub(crate) async fn run(read: Read<'_>, reach: &Reach) -> TestResult {
    let env = match contract::setup(read) {
        Ok(env) => env,
        Err(reason) => {
            skip(reason);
            return Ok(());
        }
    };
    let admitted = admit(&env.base, reach.allow_loopback).await?;
    let status = admitted.home.json(&["entware", "status"])?;
    if !eligible(&status).any(|drive| drive == env.drive) {
        return Err(SetupRefusal::DriveNotEligible.into());
    }
    let run = admitted
        .home
        .kcc(&["entware", "setup", "--drive", &env.drive])?;
    let job = serde_json::from_str::<Value>(&run.stdout).unwrap_or(Value::Null);
    let path = RciPath::from_segments(["show", "log"])?;
    let markers = match admitted
        .connection
        .client
        .post(&path, &json!({"max-lines": LOG_LINES}))
        .await
    {
        Ok(reply) => json!(installer_lines(&reply)),
        Err(error) => json!({"error": error.to_string()}),
    };
    let capture = json!({"exit": run.code, "job": job, "markers": markers});
    drop(evidence::write(&reach.evidence, evidence::SETUP, &capture)?);
    if run.code != 0_i32 {
        return Err(format!(
            "kcc entware setup exited {}: {}",
            run.code,
            run.stderr.trim()
        )
        .into());
    }
    Ok(())
}

/// The `disk_arg` of every drive `kcc entware status` lists.
fn eligible(status: &Value) -> impl Iterator<Item = &str> {
    status
        .get("drives")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|drive| drive.get("disk_arg").and_then(Value::as_str))
}

/// The installer's lines of a `show log` reply, oldest first.
fn installer_lines(reply: &RciBody) -> Vec<String> {
    let mut lines = Vec::new();
    match reply {
        RciBody::Json(response) => strings(&response.value, &mut lines),
        RciBody::Text(text) => lines.extend(text.lines().map(str::to_owned)),
        _ => {}
    }
    lines.retain(|line| line.contains(INSTALLER));
    lines
}

/// Every string inside `value`, in document order.
fn strings(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::String(text) => into.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| strings(item, into)),
        Value::Object(fields) => fields.values().for_each(|field| strings(field, into)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}
