//! Committed JSON snapshots, rewritten only when `KCC_UPDATE_SNAPSHOTS=1`.

use core::error::Error;
use std::{env, fs, path::PathBuf};

use serde_json::Value;

/// Compares `actual` with `tests/snapshots/<name>.json`, or rewrites it on request.
///
/// # Errors
/// Returns a missing or differing snapshot, or file and JSON failures.
pub(crate) fn check(name: &str, actual: &Value) -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.json"));
    let rendered = format!("{}\n", serde_json::to_string_pretty(actual)?);
    if env::var("KCC_UPDATE_SNAPSHOTS").is_ok_and(|value| value == "1") {
        fs::write(&path, rendered)?;
        return Ok(());
    }
    let committed = fs::read_to_string(&path).map_err(|error| {
        format!("snapshot {name} unreadable ({error}); run with KCC_UPDATE_SNAPSHOTS=1")
    })?;
    let expected: Value = serde_json::from_str(&committed)?;
    if &expected != actual {
        return Err(
            format!("snapshot {name} differs:\nexpected {expected}\nactual   {actual}").into(),
        );
    }
    Ok(())
}
