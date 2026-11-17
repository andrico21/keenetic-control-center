//! Step 6: the plan as the router will get it.
//!
//! The commands in their order and phases (additions, removals, connection changes
//! last), the counts, the components installed first, and the plan and report to
//! download.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_domain::configuration::{SafetyNet, apply_needs::ApplyNeeds};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};
use kcc_migrate::planner::PlannedLine;

use super::{
    access::{Migration as _, Visit},
    plan::{Built, Classified},
    reasons::Fate,
    record::Record,
    target::problem_text,
};
use crate::{
    admin_roles::permission_list,
    errors,
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
    wizard::flow::Flow as _,
};

/// What applying `record`'s plan needs: installing components first also needs
/// `Destructive`.
pub(super) fn apply_permissions(record: &Record) -> Vec<Permission> {
    let needs = ApplyNeeds::default().installing_components(!record.components().is_empty());
    SafetyNet::apply_permissions(needs)
}

/// What committing an applied plan needs.
pub(super) fn commit_permissions() -> Vec<Permission> {
    SafetyNet::apply_permissions(ApplyNeeds::default())
}

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_preview.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Migration id.
    id: String,
    /// The counts.
    facts: Vec<(String, String)>,
    /// The phases with their commands.
    phases: Vec<Phase>,
    /// Whether applying would send no command and install no component.
    nothing_to_send: bool,
    /// Components installed before the plan.
    components: Vec<String>,
    /// The URL kcc reaches the router at after the connection changes.
    reconnect: Option<String>,
    /// Whether the role may apply the plan.
    may_apply: bool,
    /// Localized reason applying is unavailable.
    apply_forbidden: String,
    /// Why the plan cannot be shown.
    problem: String,
    /// Why the apply did not start.
    error: String,
}

localized!(Panel);

/// One phase of the plan.
struct Phase {
    /// Its title.
    title: String,
    /// Its commands, redacted, with their line in the source.
    lines: Vec<(usize, String)>,
}

impl Panel {
    /// The preview with the reason the apply did not start.
    pub(super) fn refusing(mut self, error: String) -> Self {
        self.error = error;
        self
    }

    /// The preview of `visit`'s plan.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>) -> Self {
        let services = visit.services();
        let locale = services.user().locale();
        let record = visit.record();
        let target = record.target().unwrap_or_default();
        let mut panel = Self {
            shell: fragment_shell(locale),
            id: record.id().to_owned(),
            facts: Vec::new(),
            phases: Vec::new(),
            nothing_to_send: false,
            components: record.components().iter().cloned().collect(),
            reconnect: record.reconnect_url().map(str::to_owned),
            may_apply: false,
            apply_forbidden: String::new(),
            problem: String::new(),
            error: String::new(),
        };
        let missing = errors::refusal::missing(services.user(), target, &apply_permissions(record));
        panel.may_apply = missing.is_empty();
        let mut args = FluentArgs::new();
        args.set("missing", permission_list(locale, &missing));
        panel.apply_forbidden = tr(locale, keys::WEB_MIGRATE_APPLY_FORBIDDEN, Some(&args));
        let analysis = match visit.analysis().await {
            Ok(found) => found,
            Err(problem) => {
                panel.problem = problem_text(&problem, locale);
                return panel;
            }
        };
        let passwords = visit.passwords().await.unwrap_or_default();
        let (Ok(classified), Ok(built)) = (
            Classified::new(&analysis, record, &passwords),
            Built::new(&analysis, record, &passwords),
        ) else {
            panel.problem = tr(locale, keys::WEB_MIGRATE_PROBLEM_PLAN, None);
            return panel;
        };
        let plan = built.plan();
        let text = |line: &PlannedLine| {
            built
                .original(line.source_index)
                .and_then(|index| classified.items().get(index))
                .map_or_else(
                    || (0, line.display.clone()),
                    |item| {
                        (
                            item.line_no,
                            item.after.clone().unwrap_or_else(|| item.before.clone()),
                        )
                    },
                )
        };
        for (title, lines) in [
            (keys::WEB_MIGRATE_PHASE_ADDITIVE, &plan.phases.additive),
            (keys::WEB_MIGRATE_PHASE_PRUNE, &plan.phases.prune),
            (keys::WEB_MIGRATE_PHASE_MANAGEMENT, &plan.phases.management),
        ] {
            if !lines.is_empty() {
                panel.phases.push(Phase {
                    title: tr(locale, title, None),
                    lines: lines.iter().map(text).collect(),
                });
            }
        }
        let sent = plan
            .phases
            .additive
            .len()
            .saturating_add(plan.phases.prune.len())
            .saturating_add(plan.phases.management.len());
        let settings = classified.items().len();
        let migrated = migrated(&classified, record);
        panel.nothing_to_send = sent == 0 && panel.components.is_empty();
        panel.facts = [
            (keys::WEB_MIGRATE_COUNT_SETTINGS, settings),
            (keys::WEB_MIGRATE_COUNT_COMMANDS, sent),
            (
                keys::WEB_MIGRATE_COUNT_PRESENT,
                migrated.saturating_sub(sent),
            ),
            (
                keys::WEB_MIGRATE_COUNT_LEFT_OUT,
                settings.saturating_sub(migrated),
            ),
            (keys::WEB_MIGRATE_COUNT_STAY, plan.residual.len()),
        ]
        .into_iter()
        .map(|(key, count)| fact(locale, key, count))
        .collect();
        panel
    }
}

/// How many settings of `classified` the choices of `record` migrate.
fn migrated(classified: &Classified, record: &Record) -> usize {
    classified
        .items()
        .iter()
        .filter(|item| {
            let index = item.source_index;
            let excluded = record.excluded().contains(&index);
            matches!(
                Fate::of(item, classified.conflicts(index) && !excluded, excluded),
                Fate::Migrated | Fate::Conflict
            )
        })
        .count()
}

/// A count labelled `key`.
fn fact(locale: Locale, key: MessageKey, count: usize) -> (String, String) {
    let value = u64::try_from(count).unwrap_or(u64::MAX);
    (tr(locale, key, None), format::integer(locale, value))
}
