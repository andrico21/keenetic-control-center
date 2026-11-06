//! Redacted migration reports in JSON, Markdown, and standalone HTML.

use alloc::collections::BTreeMap;
use core::fmt::Write as _;

use askama::Template;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    planner::{MigrationPlan, PlanItem},
    rules::Disposition,
};

/// Current machine-readable report schema.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// One report item containing redacted commands and a localized reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "ReportItem is the public schema name for one migration report row"
)]
pub struct ReportItem {
    /// Source replay index.
    pub source_index: usize,
    /// Classification result.
    pub disposition: Disposition,
    /// Redacted source command.
    pub before: String,
    /// Redacted resulting command.
    pub after: Option<String>,
    /// Localized explanation.
    pub reason: String,
}

/// Schema-versioned, fully redacted migration report.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the public report aggregate is named MigrationReport by the plan"
)]
pub struct MigrationReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Plan identity.
    pub plan_id: String,
    /// Per-disposition item counts.
    pub counts: BTreeMap<String, usize>,
    /// Every classified item in source order.
    pub items: Vec<ReportItem>,
    /// Whether the target had non-source residual settings before apply.
    pub target_not_clean: bool,
    /// Unpruned target residual lines.
    pub residual: Vec<String>,
}

impl MigrationReport {
    /// Builds a localized report from redacted plan fields only.
    #[inline]
    #[must_use]
    pub fn from_plan(plan: &MigrationPlan, locale: Locale) -> Self {
        let items = plan
            .items
            .iter()
            .map(|item| report_item(item, locale))
            .collect::<Vec<_>>();
        let mut counts = BTreeMap::new();
        for item in &items {
            let key = disposition_name(item.disposition).to_owned();
            let count = counts.entry(key).or_insert(0_usize);
            *count = count.saturating_add(1);
        }
        Self {
            schema_version: REPORT_SCHEMA_VERSION,
            plan_id: plan.plan_id.clone(),
            counts,
            items,
            target_not_clean: plan.target_not_clean,
            residual: plan.residual.clone(),
        }
    }

    /// Serializes the report as schema-versioned JSON.
    ///
    /// # Errors
    ///
    /// Returns a serialization error when the report cannot be encoded.
    #[inline]
    pub fn to_json(&self) -> Result<String, ReportError> {
        serde_json::to_string_pretty(self).map_err(ReportError::Json)
    }

    /// Renders a self-contained Markdown report.
    #[inline]
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut output = format!("# Migration report\n\nPlan: `{}`\n\n", self.plan_id);
        output.push_str("## Counts\n\n");
        for (name, count) in &self.counts {
            let _result = writeln!(output, "- {name}: {count}");
        }
        output.push_str("\n## Items\n\n");
        for item in &self.items {
            let after = item.after.as_deref().unwrap_or("-");
            let _result = writeln!(
                output,
                "- `{}` -> `{after}` ({}, {})",
                item.before,
                disposition_name(item.disposition),
                item.reason
            );
        }
        output.push_str("\n## Residual target settings\n\n");
        for line in &self.residual {
            let _result = writeln!(output, "- `{line}`");
        }
        output
    }

    /// Renders a standalone HTML document with no external assets.
    ///
    /// # Errors
    ///
    /// Returns a template error when rendering fails.
    #[inline]
    pub fn to_html(&self) -> Result<String, ReportError> {
        ReportTemplate { report: self }
            .render()
            .map_err(ReportError::Html)
    }
}

/// Report rendering failures.
#[derive(Debug, Error)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "ReportError identifies the public report rendering domain"
)]
pub enum ReportError {
    /// JSON serialization failed.
    #[error("migration report JSON rendering failed")]
    Json(serde_json::Error),
    /// HTML template rendering failed.
    #[error("migration report HTML rendering failed")]
    Html(askama::Error),
}

/// Standalone report document.
#[derive(Template)]
#[template(
    source = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Migration report</title></head><body><main><h1>Migration report</h1><p>Plan: <code>{{ report.plan_id }}</code></p><h2>Counts</h2><ul>{% for pair in report.counts %}<li>{{ pair.0 }}: {{ pair.1 }}</li>{% endfor %}</ul><h2>Items</h2><ol>{% for item in report.items %}<li><code>{{ item.before }}</code>{% match item.after %}{% when Some with (after) %} &rarr; <code>{{ after }}</code>{% when None %}{% endmatch %}<p>{{ item.reason }}</p></li>{% endfor %}</ol><h2>Residual target settings</h2><ul>{% for line in report.residual %}<li><code>{{ line }}</code></li>{% endfor %}</ul></main></body></html>"#,
    ext = "html"
)]
struct ReportTemplate<'report> {
    /// Redacted report view.
    report: &'report MigrationReport,
}

/// Converts one redacted plan record to its localized report form.
fn report_item(item: &PlanItem, locale: Locale) -> ReportItem {
    ReportItem {
        source_index: item.source_index,
        disposition: item.disposition,
        before: report_safe_line(&item.before),
        after: item.after.as_deref().map(report_safe_line),
        reason: localized_reason(&item.reason_key, locale),
    }
}

/// Removes the typed NS3 marker as an additional defense against encoded-secret reports.
fn report_safe_line(line: &str) -> String {
    line.replace("ns3 <redacted>", "<redacted>")
}

/// Resolves embedded policy reason ids to compile-time checked Fluent keys.
fn localized_reason(reason_key: &str, locale: Locale) -> String {
    let key = match reason_key {
        "migration-reason-default-copy"
        | "migration-reason-copy-secret"
        | "migration-reason-non-critical-description" => keys::MIGRATE_REASON_COPY,
        "migration-reason-remap-reference" | "migration-reason-password-realm" => {
            keys::MIGRATE_REASON_REMAP
        }
        "migration-reason-hardware-led"
        | "migration-reason-hardware-button"
        | "migration-reason-hardware-usb"
        | "migration-reason-hardware-radio"
        | "migration-reason-hardware-printer" => keys::MIGRATE_REASON_SKIP_HARDWARE,
        "migration-reason-identity-ndns"
        | "migration-reason-identity-cloud"
        | "migration-reason-identity-certificate"
        | "migration-reason-identity-mws"
        | "migration-reason-preflight-agreement"
        | "migration-reason-kernel-tunable"
        | "migration-reason-identity-mac" => keys::MIGRATE_REASON_SKIP_IDENTITY,
        "migration-reason-install-component"
        | "migration-reason-scalar-conflict"
        | "migration-reason-management-reconnect" => keys::MIGRATE_REASON_NEEDS_INPUT,
        "migration-reason-operator-prune" => keys::MIGRATE_REASON_PRUNE,
        _ => keys::MIGRATE_REASON_UNSUPPORTED,
    };
    tr(locale, key, None)
}

/// Stable serialization name for a disposition.
const fn disposition_name(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::Copy => "copy",
        Disposition::Remap => "remap",
        Disposition::SkipHardware => "skip-hardware",
        Disposition::SkipIdentity => "skip-identity",
        Disposition::NeedsInput => "needs-input",
        Disposition::Unsupported => "unsupported",
        Disposition::Conflict => "conflict",
    }
}
