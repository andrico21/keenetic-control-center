//! Step 6: the commands as the router will get them, in order, with secret values
//! redacted; Reveal shows them in plaintext with `RevealSecrets`, and Apply asks first.

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
    access::Visit,
    lines::{redacted, secret},
    plan::{Basis, Refused, plan_problem},
    target::problem_text,
};
use crate::{
    WebState,
    admin_roles::permission_list,
    errors,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::allowed},
};

/// What applying a preset needs; a preset never installs components.
pub(super) fn apply_permissions() -> Vec<Permission> {
    SafetyNet::apply_permissions(ApplyNeeds::default())
}

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/presets_preview.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Run id.
    id: String,
    /// The counts.
    facts: Vec<(String, String)>,
    /// The phases: title and commands with their number.
    phases: Vec<(String, Vec<(usize, String)>)>,
    /// Whether the role may apply the plan.
    may_apply: bool,
    /// Localized reason applying is unavailable.
    apply_forbidden: String,
    /// Whether the role may reveal commands that carry secret values.
    may_reveal: bool,
    /// Why the plan cannot be shown.
    problem: String,
    /// Why the apply did not start.
    error: String,
}

localized!(Panel);

impl Panel {
    /// The preview of `visit`'s plan for `state`'s user.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>, state: &WebState) -> Self {
        let services = visit.services();
        let user = services.user();
        let locale = user.locale();
        let record = visit.record();
        let target = record.target().unwrap_or_default();
        let mut panel = Self {
            shell: fragment_shell(locale),
            id: record.id().to_owned(),
            facts: Vec::new(),
            phases: Vec::new(),
            may_apply: false,
            apply_forbidden: String::new(),
            may_reveal: false,
            problem: String::new(),
            error: String::new(),
        };
        let missing = errors::refusal::missing(user, target, &apply_permissions());
        panel.may_apply = missing.is_empty();
        let mut args = FluentArgs::new();
        args.set("missing", permission_list(locale, &missing));
        panel.apply_forbidden = tr(locale, keys::WEB_PRESETS_APPLY_FORBIDDEN, Some(&args));
        let basis = match Basis::of(visit).await {
            Ok(found) => found,
            Err(problem) => {
                panel.problem = problem_text(&problem, locale);
                return panel;
            }
        };
        let total = basis.preset().lines.len();
        let all = match basis.plan(record) {
            Ok(found) => found,
            Err(error) => {
                panel.problem = problem_text(&plan_problem(&error), locale);
                return panel;
            }
        };
        let request = match basis.request(record, state, services) {
            Ok(found) => found,
            Err(Refused::Plan(error)) => {
                panel.problem = problem_text(&plan_problem(&error), locale);
                return panel;
            }
            Err(Refused::Apply(_refused)) => {
                panel.problem = tr(locale, keys::WEB_MIGRATE_PROBLEM_PLAN, None);
                return panel;
            }
        };
        let phases = &request.plan.phases;
        let shown = |lines: &[PlannedLine]| {
            lines
                .iter()
                .map(|line| {
                    (
                        line.source_index.saturating_add(1),
                        redacted(line.expose_command()),
                    )
                })
                .collect::<Vec<_>>()
        };
        for (title, lines) in [
            (keys::WEB_MIGRATE_PHASE_ADDITIVE, &phases.additive),
            (keys::WEB_MIGRATE_PHASE_PRUNE, &phases.prune),
        ] {
            if !lines.is_empty() {
                panel.phases.push((tr(locale, title, None), shown(lines)));
            }
        }
        let commands = phases.additive.len().saturating_add(phases.prune.len());
        let kept = |item_index: usize| !record.excluded().contains(&item_index);
        let present = all
            .items
            .iter()
            .filter(|item| kept(item.index) && item.reason == "preset-already-present")
            .count();
        let unsent = all
            .items
            .len()
            .saturating_sub(commands)
            .saturating_sub(present);
        panel.may_reveal = allowed(user, target, &[Permission::RevealSecrets])
            && phases
                .additive
                .iter()
                .chain(&phases.prune)
                .any(|line| secret(line.expose_command()));
        panel.facts = [
            (keys::WEB_PRESETS_COUNT_SETTINGS, total),
            (keys::WEB_MIGRATE_COUNT_COMMANDS, commands),
            (keys::WEB_MIGRATE_COUNT_PRESENT, present),
            (keys::WEB_MIGRATE_COUNT_LEFT_OUT, unsent),
        ]
        .into_iter()
        .map(|(key, count)| fact(locale, key, count))
        .collect();
        panel
    }

    /// The preview with the reason the apply did not start.
    pub(super) fn refusing(mut self, error: String) -> Self {
        self.error = error;
        self
    }
}

/// A count labelled `key`.
fn fact(locale: Locale, key: MessageKey, count: usize) -> (String, String) {
    let value = u64::try_from(count).unwrap_or(u64::MAX);
    (tr(locale, key, None), format::integer(locale, value))
}
