//! The committed monitoring artefacts agree with the metric catalogue.
#![expect(
    clippy::std_instead_of_alloc,
    clippy::tests_outside_test_module,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test crate: assertions define the contract"
)]

use core::error::Error;
use std::{collections::BTreeSet, fs, path::PathBuf};

use kcc_telemetry::metrics::{
    catalogue::{MetricKind, find},
    docs::markdown,
};

/// Repository root.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `keenetic_*` / `kcc_*` identifier in `text`.
fn metric_names(text: &str) -> BTreeSet<&str> {
    let mut names = BTreeSet::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        let rest = text.get(start..).unwrap_or_default();
        let preceded = start
            .checked_sub(1)
            .and_then(|index| bytes.get(index))
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
        if !preceded && (rest.starts_with("keenetic_") || rest.starts_with("kcc_")) {
            let length = rest
                .bytes()
                .take_while(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'
                })
                .count();
            if let Some(name) = rest.get(..length) {
                let _inserted: bool = names.insert(name);
            }
            start = start.saturating_add(length);
        } else {
            start = start.saturating_add(1);
        }
    }
    names
}

/// Whether `name` is a catalogued family or a histogram series of one.
fn catalogued(name: &str) -> bool {
    find(name).is_some()
        || ["_bucket", "_count", "_sum"].iter().any(|suffix| {
            name.strip_suffix(suffix)
                .and_then(find)
                .is_some_and(|family| family.kind == MetricKind::Histogram)
        })
}

/// Every metric the dashboard and the alert rules query exists in the catalogue.
#[test]
fn dashboard_and_alerts_use_only_catalogued_metrics() -> Result<(), Box<dyn Error>> {
    for file in [
        "deploy/monitoring/grafana-dashboard.json",
        "deploy/monitoring/prometheus-alerts.yaml",
        "deploy/monitoring/prometheus-alerts.test.yaml",
    ] {
        let text = fs::read_to_string(root().join(file))?;
        let names = metric_names(&text);
        assert!(names.len() >= 5, "{file}: found only {names:?}");
        let unknown: Vec<&str> = names.into_iter().filter(|name| !catalogued(name)).collect();
        assert!(
            unknown.is_empty(),
            "{file} uses uncatalogued metrics {unknown:?}"
        );
    }
    Ok(())
}

/// `docs/METRICS.md` is the output of `cargo xtask gen-metric-docs`.
#[test]
fn committed_metric_docs_match_the_catalogue() -> Result<(), Box<dyn Error>> {
    let committed = fs::read_to_string(root().join("docs/METRICS.md"))?;
    assert!(
        committed == markdown(),
        "docs/METRICS.md is stale; run `cargo xtask gen-metric-docs`"
    );
    Ok(())
}
