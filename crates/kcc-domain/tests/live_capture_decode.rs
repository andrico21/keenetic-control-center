//! Replays a read-only capture of a real router through a fake router against kcc's reads.
//!
//! Set `KCC_LIVE_CAPTURE_DIR` to the absolute path of a capture directory (the
//! `kcc-capture` output with its `manifest.json`) and run with `--ignored`; each `live_*`
//! test then fails with the decode error of its read. Without the variable every test
//! logs `live-skip:no-capture-dir` and passes. `KCC_LIVE_FIXTURE_DIR` (absolute) replaces
//! the committed real-shape fixture directory of the parity test.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

extern crate alloc;

#[path = "live_capture_decode/capture.rs"]
mod capture;
#[path = "live_capture_decode/reads.rs"]
mod reads;
#[path = "live_capture_decode/shape.rs"]
mod shape;

use core::fmt::Display;
use std::{env, fs, path::PathBuf};

use kcc_domain::{RouterCtx, clients};
use serde_json::{Value, json};

use crate::{
    capture::{CAPTURE_DIR, Capture, TestResult},
    shape::differences,
};

/// The variable that replaces the committed real-shape fixture directory.
const FIXTURE_DIR: &str = "KCC_LIVE_FIXTURE_DIR";

/// Runs `read` against the replayed capture; skips without a capture directory.
///
/// # Errors
///
/// Replay setup errors, or the read's error, whose Display the message carries.
pub(crate) async fn decodes<T, E, F>(read: F) -> TestResult
where
    F: AsyncFnOnce(&RouterCtx) -> Result<T, E>,
    E: Display,
{
    let Some(directory) = capture::directory()? else {
        return Ok(());
    };
    let (router, handle) = Capture::load(&directory)?.spawn().await?;
    let outcome = read(&router).await;
    handle.shutdown().await?;
    outcome
        .map(drop)
        .map_err(|error| format!("the captured answer did not decode: {error}").into())
}

/// The real-shape fixtures the parity test compares.
fn fixture_directory() -> PathBuf {
    env::var_os(FIXTURE_DIR).map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../kcc-testkit/fixtures/KN-1811/real-5.1.10")
        },
        PathBuf::from,
    )
}

/// Compares every `.json` real-shape fixture with the captured item of the same name.
fn parity() -> TestResult {
    let Some(directory) = capture::directory()? else {
        return Ok(());
    };
    let fixtures = fixture_directory();
    if !fixtures.is_dir() {
        tracing::info!("no real-shape fixture directory yet: nothing to compare");
        return Ok(());
    }
    let captured = Capture::load(&directory)?;
    let mut names: Vec<PathBuf> = fs::read_dir(&fixtures)?
        .map(|entry| entry.map(|found| found.path()))
        .collect::<Result<_, _>>()?;
    names.sort();
    let mut problems = Vec::new();
    for path in names {
        let Some(item) = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"))
        else {
            continue;
        };
        let fixture: Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        match captured.json(item) {
            Some(answer) => problems.extend(
                differences(&fixture, answer)
                    .into_iter()
                    .map(|difference| format!("{item}: {difference}")),
            ),
            None => problems.push(format!("{item}: no JSON item of that name in the capture")),
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "real-shape fixtures differ from the capture:\n{}",
            problems.join("\n")
        )
        .into())
    }
}

/// Todo 12: every committed real-shape fixture has the paths and kinds of its captured
/// item.
#[test]
#[ignore = "needs KCC_LIVE_CAPTURE_DIR"]
fn live_real_shape_fixtures_match_the_capture() -> TestResult {
    parity()
}

/// Todo 12: without a capture directory a read and the parity check log `live-skip` and
/// pass, so a plain run stays green.
#[tokio::test]
async fn without_a_capture_directory_the_harness_skips() -> TestResult {
    if env::var_os(CAPTURE_DIR).is_some() {
        tracing::info!("{CAPTURE_DIR} is set: the ignored tests replay it");
        return Ok(());
    }
    decodes(async |router: &RouterCtx| clients::read_clients(router).await).await?;
    parity()
}

/// Todo 12: shape differences name paths and kinds, never values.
///
/// Array lengths do not count. The masking of map keys that don't match
/// `^[A-Za-z][A-Za-z0-9_-]{0,63}$` is exercised by `"Odd Key 9"` with different kinds
/// on each side.
#[test]
fn shape_differences_name_paths_and_kinds_without_values() {
    let fixture =
        json!({"system": {"uptime": 4_711_u32, "Odd Key 9": 1_i64}, "host": [{"mac": "m"}]});
    let captured = json!({
        "system": {"uptime": "planted-uptime", "Odd Key 9": "y"},
        "host": [{"mac": "a"}, {"mac": "b"}, {"mac": "c"}]
    });

    let found = differences(&fixture, &captured);

    assert_eq!(
        found,
        [
            "$.system.* (number) only in the fixture",
            "$.system.uptime (number) only in the fixture",
            "$.system.* (string) only in the capture",
            "$.system.uptime (string) only in the capture"
        ]
    );
    assert!(!found.iter().any(|line| line.contains("Odd Key 9")
        || line.contains("planted")
        || line.contains("4711")));
}
