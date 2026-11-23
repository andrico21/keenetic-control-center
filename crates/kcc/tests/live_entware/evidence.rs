//! Evidence files of the live suites: anonymized with the capture tool's anonymizer before
//! they are written, so the owner can commit them.
#![expect(
    clippy::panic_in_result_fn,
    reason = "evidence tests fail by asserting"
)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use kcc_testkit::anonymize::Anonymizer;
use serde_json::{Value, json};
use tempfile::TempDir;

use super::TestResult;

/// The read-only probe's capture.
pub(crate) const PROBE: &str = "live-entware-probe.json";
/// The guided setup's record.
pub(crate) const SETUP: &str = "live-entware-setup.json";
/// The SSH suite's record.
pub(crate) const SSH: &str = "live-entware-ssh.json";

/// The workspace evidence directory the owner's runs write to.
pub(crate) fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.omo/evidence")
}

/// Anonymizes `capture` and writes it to `directory/name`.
///
/// # Errors
/// Returns anonymizer, serialization or file failures.
pub(crate) fn write(directory: &Path, name: &str, capture: &Value) -> TestResult<PathBuf> {
    let clean = Anonymizer::new().json(capture)?;
    fs::create_dir_all(directory)?;
    let path = directory.join(name);
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&clean)?),
    )?;
    tracing::info!(path = %path.display(), "evidence written");
    Ok(path)
}

/// Todo 19: a capture loses serials, MACs, private addresses and uuids before it is
/// written; its field names and flags stay.
#[test]
fn captures_are_anonymized_before_they_are_written() -> TestResult {
    let directory = TempDir::new()?;
    let serial = format!("S{}", 1_234_567_890_123_u64);
    let mac = format!("{}:11:22:33:44:55", "a4");
    let address = format!("{}.{}.7.9", 192_u8, 168_u8);
    let uuid = format!("{}-4f2a-9c1b-0d1e2f3a4b5c", "1b2c3d4e");
    let capture = json!({
        "identification": {"serial": serial},
        "media": [{"id": "Media0", "uuid": uuid, "uuid_present": true, "note": mac}],
        "rc_opkg": {"disk": format!("{address}:/")},
    });
    let path = write(directory.path(), PROBE, &capture)?;
    let text = fs::read_to_string(path)?;
    for planted in [&serial, &mac, &address, &uuid] {
        assert!(!text.contains(planted.as_str()), "{planted} kept: {text}");
    }
    let written: Value = serde_json::from_str(&text)?;
    assert_eq!(
        written.pointer("/media/0/uuid_present"),
        Some(&Value::Bool(true))
    );
    assert_eq!(written.pointer("/media/0/id"), Some(&Value::from("Media0")));
    Ok(())
}
