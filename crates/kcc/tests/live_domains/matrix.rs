//! Firmware-matrix recording of this suite, the auth matrix, and the campaign skip lines.

use core::error::Error;
use std::{env, path::PathBuf};

use kcc_rci::capabilities::{AuthSchemeKind, RouterInfo};
use kcc_testkit::live_matrix::{self, Outcome, Run, Suite};

use super::{
    TestResult,
    campaign::{Options, WriteMode},
    gate,
};

/// Suite name of the authentication matrix.
pub(crate) const AUTH_SUITE: &str = "live_auth_matrix";

/// Suites that cannot run on firmware lines without hardware.
const ALL_SUITES: [&str; 9] = [
    "live_smoke",
    "live_domains",
    AUTH_SUITE,
    "live_migration",
    "live_presets",
    "live_mcp",
    "web_ui_playwright",
    "container_podman",
    "live_campaign_matrix",
];

/// Suites driven by scripts outside `cargo test`, recorded here when they cannot run.
const SCRIPT_SUITES: [&str; 2] = ["web_ui_playwright", "container_podman"];

/// `.omo/evidence/task-51-keenetic-control-center.json` in the workspace.
pub(crate) fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.omo/evidence/task-51-keenetic-control-center.json")
}

/// Records one suite outcome under `run`.
pub(crate) fn record(run: &Run, suite: Suite<'_>) -> TestResult {
    Ok(live_matrix::record(&path(), run, suite)?)
}

/// Records a `live-skip` of `name` without a router.
pub(crate) fn skip(name: &str, reason: &str) -> TestResult {
    Ok(live_matrix::record_skip(&path(), name, reason)?)
}

/// The scheme kcc is expected to exercise: ndw4 when advertised (5.2+), ndw2 otherwise.
fn expected_scheme(info: &RouterInfo) -> &'static str {
    if info.auth_schemes.contains(&AuthSchemeKind::Ndw4) {
        "ndw4"
    } else {
        "ndw2"
    }
}

/// Logs in read-only, records the advertised schemes and the one kcc authenticated with.
///
/// # Errors
/// Returns refusals and transport failures; the outcome is recorded either way.
// cancel-safe: reads only.
pub(crate) async fn auth(mut options: Options) -> TestResult {
    options.write = WriteMode::ReadOnly;
    let result: Result<(Run, String), Box<dyn Error>> = async {
        let opened = gate::open(&options).await?;
        let info =
            RouterInfo::detect(&opened.connection.session, &opened.connection.router).await?;
        let advertised = info
            .auth_schemes
            .iter()
            .map(|scheme| format!("{scheme:?}").to_lowercase())
            .collect::<Vec<_>>()
            .join(",");
        let reason = format!(
            "authenticated; advertised [{advertised}]; exercised {}",
            expected_scheme(&info)
        );
        Ok((Run::observed(&opened.serial, &info), reason))
    }
    .await;
    match result {
        Ok((run, reason)) => {
            tracing::info!(%reason, "auth matrix");
            record(&run, Suite::new(AUTH_SUITE, Outcome::Pass, &reason))
        }
        Err(error) => {
            record(
                &Run::unavailable(),
                Suite::new(AUTH_SUITE, Outcome::Fail, &error.to_string()),
            )?;
            Err(error)
        }
    }
}

/// Records the firmware lines without hardware and, without a live router, the script suites.
pub(crate) fn campaign() -> TestResult {
    for firmware in ["4.3 LTS", "5.0"] {
        let run = Run::without_hardware(firmware);
        for suite in ALL_SUITES {
            let skipped = Suite::new(suite, Outcome::LiveSkip, "no 4.3/5.0 hardware");
            record(&run, skipped)?;
        }
    }
    let unset = env::var("KCC_LIVE_URL").map_or(true, |url| url.trim().is_empty());
    if unset {
        tracing::warn!("live-skip:kcc_live_url-unset");
        for suite in SCRIPT_SUITES.into_iter().chain(["live_campaign_matrix"]) {
            skip(suite, "kcc_live_url-unset")?;
        }
    }
    Ok(())
}
