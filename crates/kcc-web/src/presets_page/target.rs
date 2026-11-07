//! Step 2: the target router and its warnings, as in the migration wizard.
//!
//! Choosing a target reads its inventory (nothing is written): a router outside the
//! role's `Migrate` scope is refused before any request, firmware older than the
//! settings' is refused (`TargetFirmwareOlder`), and the warnings show. Continuing needs
//! the acknowledgement of a documentation-based firmware tier, which the audit log
//! records. The submits are `target_submit`.

use askama::Template;
use fluent_bundle::FluentArgs;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_migrate::inventory::TargetInventory;
use kcc_rci::capabilities::{SupportTier, SystemMode};

use super::{access::Visit, steps::Origin};
use crate::{
    migrate_wizard::{analysis::Problem, warnings::mode_text},
    page::{Localize, Shell},
    page_kit::context::fragment_shell,
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/presets_target.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Run id.
    id: String,
    /// Routers the user may apply to, and whether each is chosen.
    routers: Vec<(String, bool)>,
    /// The router select's error.
    router_error: String,
    /// Why the chosen target cannot be used.
    problem: String,
    /// The chosen target's identity and warnings.
    report: Option<Report>,
    /// Whether the acknowledgement was given.
    acknowledged: bool,
    /// The acknowledgement's error.
    ack_error: String,
}

impl Localize for Panel {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// The target's identity and warnings.
pub(super) struct Report {
    /// Model, firmware, support tier, operating mode.
    facts: Vec<(String, String)>,
    /// Notice tone and sentence of each warning.
    warnings: Vec<(&'static str, String)>,
    /// Whether the firmware tier needs the acknowledgement.
    needs_ack: bool,
    /// Whether kcc cannot apply settings to the firmware at all.
    unsupported: bool,
}

impl Report {
    /// The report of `target` in `locale`.
    fn new(target: &TargetInventory, locale: Locale) -> Self {
        let info = &target.info;
        let (tier, needs_ack, unsupported) = match info.support_tier() {
            SupportTier::HardwareVerified => (keys::WEB_TIER_VERIFIED, false, false),
            SupportTier::DocumentationBased => (keys::WEB_TIER_DOCUMENTATION, true, false),
            SupportTier::Unsupported | _ => (keys::WEB_TIER_UNSUPPORTED, false, true),
        };
        let router_mode = matches!(target.system_mode, Some(SystemMode::Router));
        let warnings = [
            (needs_ack, "warning", keys::WEB_MIGRATE_WARNING_TIER),
            (unsupported, "error", keys::WEB_PRESETS_PROBLEM_UNSUPPORTED),
            (!router_mode, "warning", keys::WEB_MIGRATE_WARNING_MODE),
        ]
        .into_iter()
        .filter(|(shown, _, _)| *shown)
        .map(|(_, tone, key)| (tone, tr(locale, key, None)))
        .collect();
        let model = match (info.version.model.as_deref(), info.hw_id()) {
            (Some(name), Some(id)) if name != id => format!("{name} ({id})"),
            (Some(name), _) => name.to_owned(),
            (None, Some(id)) => id.to_owned(),
            (None, None) => String::new(),
        };
        let mode = target.system_mode.as_ref().map_or_else(
            || tr(locale, keys::WEB_KIT_NOT_REPORTED, None),
            |found| mode_text(found, locale),
        );
        let fact = |key: MessageKey, value: String| (tr(locale, key, None), value);
        Self {
            facts: vec![
                fact(keys::DOMAINS_MODEL, model),
                fact(
                    keys::DOMAINS_FIRMWARE,
                    info.firmware
                        .map_or_else(String::new, |version| version.to_string()),
                ),
                fact(keys::WEB_MIGRATE_TIER, tr(locale, tier, None)),
                fact(keys::WEB_MIGRATE_MODE, mode),
            ],
            warnings,
            needs_ack,
            unsupported,
        }
    }
}

impl Panel {
    /// The panel of `visit`, with the chosen target's report when it can be read.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>) -> Self {
        let mut panel = Self::base(visit).await;
        if visit.record().target().is_some() {
            let locale = visit.services().user().locale();
            let read = match visit.preset() {
                Ok(preset) => visit.inventory(&preset).await,
                Err(problem) => Err(problem),
            };
            match read {
                Ok(inventory) => panel.report = Some(Report::new(&inventory, locale)),
                Err(problem) => panel.problem = problem_text(&problem, locale),
            }
        }
        panel
    }

    /// The panel of `visit` without reading the target.
    // cancel-safe: reads only.
    async fn base(visit: &Visit<'_>) -> Self {
        let services = visit.services();
        let record = visit.record();
        let source = match record.origin() {
            Origin::Copy => record.source_router(),
            Origin::Preset { id: _, name: _ } => None,
        };
        let routers = match services.fleet().visible(services.user().role()).await {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| entry.profile.id)
                .filter(|router| services.may_migrate(router) && Some(router.as_str()) != source)
                .map(|router| {
                    let selected = record.target() == Some(router.as_str());
                    (router, selected)
                })
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "preset target: routers could not be listed");
                Vec::new()
            }
        };
        Self {
            shell: fragment_shell(services.user().locale()),
            id: record.id().to_owned(),
            routers,
            router_error: String::new(),
            problem: String::new(),
            report: None,
            acknowledged: record.acknowledged(),
            ack_error: String::new(),
        }
    }

    /// The panel of `visit` without reading the target, with the router select's error
    /// and why the target cannot be used.
    // cancel-safe: reads only.
    pub(super) async fn refused(visit: &Visit<'_>, router_error: String, problem: String) -> Self {
        let mut panel = Self::base(visit).await;
        panel.router_error = router_error;
        panel.problem = problem;
        panel
    }

    /// Whether the read target's tier needs the acknowledgement, and whether kcc cannot
    /// apply settings to it at all; `None` when the target was not read.
    pub(super) fn tier(&self) -> Option<(bool, bool)> {
        self.report
            .as_ref()
            .map(|report| (report.needs_ack, report.unsupported))
    }

    /// Asks for the acknowledgement of the documentation-based tier, in `locale`.
    pub(super) fn require_ack(&mut self, locale: Locale) {
        self.ack_error = tr(locale, keys::WEB_MIGRATE_ACK_REQUIRED, None);
    }
}

/// The sentence explaining `problem` for a run's settings and target.
pub(super) fn problem_text(problem: &Problem, locale: Locale) -> String {
    match problem {
        Problem::Source | Problem::FirmwareRequired => {
            tr(locale, keys::WEB_PRESETS_PROBLEM_SETTINGS, None)
        }
        Problem::FirmwareOlder { source, target } => {
            let mut args = FluentArgs::new();
            args.set("version", target.clone());
            args.set("value", source.clone());
            tr(
                locale,
                keys::WEB_PRESETS_PROBLEM_FIRMWARE_OLDER,
                Some(&args),
            )
        }
        Problem::Unsupported => tr(locale, keys::WEB_PRESETS_PROBLEM_UNSUPPORTED, None),
        Problem::Unreachable => tr(locale, keys::WEB_MIGRATE_PROBLEM_UNREACHABLE, None),
    }
}
