//! Normalized configuration and health verification.

use alloc::collections::BTreeSet;
use core::fmt::Write as _;

use kcc_config::config_text::{Ast, flatten};
use kcc_rci::{ConfigKind, RciBody, RciPath};
use md5::{Digest as _, Md5};
use secrecy::ExposeSecret as _;

use super::{Applier, ApplyError, normalize};
use crate::source::SourceConfig;

/// Checks every planned addition and removal against canonical running configuration.
///
/// # Errors
/// Returns read-back, missing-line, or health-check failures.
// cancel-safe: verification only reads router state.
pub(super) async fn run(applier: &mut Applier) -> Result<(), ApplyError> {
    let client = applier.changes.client();
    let bytes = client
        .download_config(ConfigKind::Running)
        .await
        .map_err(|_error| ApplyError::Unreachable)?;
    let source = SourceConfig::from_bytes(bytes.expose_secret())
        .map_err(|_error| ApplyError::Verification)?;
    let actual = flatten(&source.ast)
        .iter()
        .map(|line| normalize::line(&line.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = applier
        .plan
        .expected_lines
        .iter()
        .map(|line| normalize::line(line.expose_secret()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let baseline = SourceConfig::from_bytes(applier.baseline.expose_secret())
        .map_err(|_error| ApplyError::Verification)?;
    let original_lines = flatten(&baseline.ast)
        .iter()
        .map(|line| normalize::line(&line.to_string()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let unexpected = actual
        .difference(&expected)
        .filter(|line| !original_lines.contains(*line))
        .any(|line| {
            !(applier.options.admin_password.is_some()
                && line.starts_with("user admin password stored "))
        });
    if unexpected {
        return Err(ApplyError::Verification);
    }
    if !expected.is_subset(&actual) {
        return Err(ApplyError::Verification);
    }
    let replaced = expected
        .iter()
        .map(|line| normalize::identity(line))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let pruned = applier
        .plan
        .phases
        .prune
        .iter()
        .filter_map(|line| line.expose_command().strip_prefix("no "))
        .map(normalize::line)
        .collect::<Result<BTreeSet<_>, _>>()?;
    for missing in original_lines.difference(&actual) {
        if !pruned.contains(missing) && !replaced.contains(&normalize::identity(missing)?) {
            return Err(ApplyError::Verification);
        }
    }
    for line in &applier.plan.phases.prune {
        if let Some(removed) = line.expose_command().strip_prefix("no ")
            && actual.contains(&normalize::line(removed)?)
        {
            return Err(ApplyError::Verification);
        }
    }
    health(&client).await?;
    applier.report.residual_count = actual.difference(&expected).count();
    applier.report.residual = actual
        .difference(&expected)
        .map(|_line| "<redacted>".to_owned())
        .collect();
    applier.report.verified = true;
    Ok(())
}

/// Requires positive internet reachability and an active management bridge link.
///
/// # Errors
/// Returns failed or malformed health checks.
// cancel-safe: health checks only read router state.
async fn health(client: &kcc_rci::RciClient) -> Result<(), ApplyError> {
    let path = RciPath::from_segments(["show", "internet", "status"])
        .map_err(|_error| ApplyError::Validation)?;
    let RciBody::Json(internet) = client
        .get(&path, &())
        .await
        .map_err(|_error| ApplyError::Verification)?
    else {
        return Err(ApplyError::Verification);
    };
    if internet
        .value
        .get("internet")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err(ApplyError::Verification);
    }
    let interface_path =
        RciPath::from_segments(["show", "interface"]).map_err(|_error| ApplyError::Validation)?;
    let RciBody::Json(interfaces) = client
        .get(&interface_path, &())
        .await
        .map_err(|_error| ApplyError::Verification)?
    else {
        return Err(ApplyError::Verification);
    };
    if interfaces
        .value
        .pointer("/Bridge0/link")
        .and_then(serde_json::Value::as_str)
        != Some("up")
    {
        return Err(ApplyError::Verification);
    }
    Ok(())
}

/// Matches the planner's fallback fingerprint for headerless sources.
pub(super) fn normalized_digest(ast: &Ast) -> String {
    let lines = flatten(ast)
        .iter()
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>();
    digest(&lines.into_iter().collect::<Vec<_>>().join("\n"))
}

/// Formats the MD5 used by router drift identities.
pub(super) fn digest(text: &str) -> String {
    let mut output = String::with_capacity(32);
    for byte in Md5::digest(text.as_bytes()) {
        let _result = write!(output, "{byte:02x}");
    }
    output
}
