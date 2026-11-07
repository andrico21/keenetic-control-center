//! Firmware matrix of the live campaign: which router, firmware and suites ran.
//!
//! [`record`] upserts one suite outcome into a JSON document of the form
//! `{"runs": [{router_serial_hash, model, firmware_title, auth_scheme, suites: [{name,
//! outcome, reason}]}]}`. A run is identified by its four keys; a suite by its name within
//! the run. The router serial is stored only as a truncated SHA-256 hash, and no other
//! router value than the model, the firmware title and the authentication scheme is kept.

use core::fmt::Write as _;
use std::{fs, io, path::Path, sync::Mutex};

use kcc_rci::capabilities::{AuthSchemeKind, RouterInfo};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

/// Serializes read-modify-write of the matrix file between test threads of one process.
static FILE_LOCK: Mutex<()> = Mutex::new(());

/// Bytes of the serial hash kept in the matrix (16 hex digits).
const SERIAL_HASH_BYTES: usize = 8;

/// The router a suite ran against, or why no router was available.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Run {
    /// Truncated SHA-256 of the serial; `None` without a router.
    pub router_serial_hash: Option<String>,
    /// Model or hardware id.
    pub model: Option<String>,
    /// Exact firmware title.
    pub firmware_title: Option<String>,
    /// Authentication scheme the router advertises first.
    pub auth_scheme: Option<String>,
}

impl Run {
    /// A run without a reachable router.
    #[inline]
    #[must_use]
    pub fn unavailable() -> Self {
        Self::default()
    }

    /// A firmware line that has no hardware to run on.
    #[inline]
    #[must_use]
    pub fn without_hardware(firmware_title: &str) -> Self {
        Self {
            firmware_title: Some(firmware_title.to_owned()),
            ..Self::default()
        }
    }

    /// A run against a detected router; only the hash of `serial` is kept.
    #[inline]
    #[must_use]
    pub fn observed(serial: &str, info: &RouterInfo) -> Self {
        let digest = Sha256::digest(serial.as_bytes());
        let mut hash = String::new();
        for byte in digest.iter().take(SERIAL_HASH_BYTES) {
            let _result = write!(hash, "{byte:02x}");
        }
        Self {
            router_serial_hash: Some(hash),
            model: info
                .version
                .model
                .clone()
                .or_else(|| info.hw_id().map(ToOwned::to_owned)),
            firmware_title: info.version.title.clone(),
            auth_scheme: info.auth_schemes.first().map(|scheme| match scheme {
                AuthSchemeKind::Ndw2 => "ndw2".to_owned(),
                AuthSchemeKind::Ndw4 => "ndw4".to_owned(),
                AuthSchemeKind::Other(name) => name.clone(),
                _ => "unknown".to_owned(),
            }),
        }
    }

    /// The run's identifying keys as JSON.
    fn keys(&self) -> Map<String, Value> {
        let mut keys = Map::new();
        for (name, value) in [
            ("router_serial_hash", &self.router_serial_hash),
            ("model", &self.model),
            ("firmware_title", &self.firmware_title),
            ("auth_scheme", &self.auth_scheme),
        ] {
            drop(keys.insert(name.to_owned(), json!(value)));
        }
        keys
    }
}

/// How one suite ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Every assertion held against the router.
    Pass,
    /// The suite ran and failed.
    Fail,
    /// The suite did not run; the reason says why.
    LiveSkip,
}

impl Outcome {
    /// The matrix spelling.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::LiveSkip => "live-skip",
        }
    }
}

/// One suite result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Suite<'suite> {
    /// Suite name, unique within a run.
    pub name: &'suite str,
    /// Outcome.
    pub outcome: Outcome,
    /// Why, for a skip or a failure; empty for a pass.
    pub reason: &'suite str,
}

impl<'suite> Suite<'suite> {
    /// Creates a suite result.
    #[inline]
    #[must_use]
    pub const fn new(name: &'suite str, outcome: Outcome, reason: &'suite str) -> Self {
        Self {
            name,
            outcome,
            reason,
        }
    }
}

/// Upserts a `live-skip` of suite `name` under the run without a router.
///
/// A `kcc_live_<name>-unset` reason becomes `no live router (KCC_LIVE_<NAME> unset)`; any
/// other reason is kept verbatim.
///
/// # Errors
///
/// Returns read, parse or write failures of the matrix file.
#[inline]
pub fn record_skip(path: &Path, name: &str, reason: &str) -> io::Result<()> {
    let text = reason.strip_suffix("-unset").map_or_else(
        || reason.to_owned(),
        |variable| format!("no live router ({} unset)", variable.to_uppercase()),
    );
    record(
        path,
        &Run::unavailable(),
        Suite::new(name, Outcome::LiveSkip, &text),
    )
}

/// Upserts `suite` under `run` in the matrix file at `path`, creating it when absent.
///
/// # Errors
///
/// Returns read, parse or write failures of the matrix file.
#[inline]
pub fn record(path: &Path, run: &Run, suite: Suite<'_>) -> io::Result<()> {
    let _guard = FILE_LOCK
        .lock()
        .map_err(|_poisoned| io::Error::other("matrix lock poisoned"))?;
    let mut document = match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).map_err(io::Error::other)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => json!({"runs": []}),
        Err(error) => return Err(error),
    };
    let runs = document
        .get_mut("runs")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::other("matrix has no runs array"))?;
    let keys = run.keys();
    let matches = |entry: &Value| {
        keys.iter()
            .all(|(name, value)| entry.get(name) == Some(value))
    };
    let index = runs.iter().position(matches).unwrap_or_else(|| {
        let mut entry = keys.clone();
        drop(entry.insert("suites".to_owned(), json!([])));
        runs.push(Value::Object(entry));
        runs.len().saturating_sub(1)
    });
    let suites = runs
        .get_mut(index)
        .and_then(|entry| entry.get_mut("suites"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| io::Error::other("matrix run has no suites array"))?;
    suites.retain(|entry| entry.get("name").and_then(Value::as_str) != Some(suite.name));
    suites.push(json!({
        "name": suite.name,
        "outcome": suite.outcome.as_str(),
        "reason": suite.reason,
    }));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = serde_json::to_string_pretty(&document).map_err(io::Error::other)?;
    fs::write(path, format!("{text}\n"))
}
