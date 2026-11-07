//! Step 2: the target router and its warnings.
//!
//! Choosing a target reads its inventory (nothing is written): a target outside the
//! role's `Migrate` scope is refused before any request, older firmware than the
//! source's is refused (`TargetFirmwareOlder`), and the warnings show. Continuing needs
//! the acknowledgement of a documentation-based firmware tier, which the audit log
//! records. A restore's target is the backup's own router.

use alloc::sync::Arc;
use core::str::FromStr as _;

use askama::Template;
use axum::{
    Extension, Form,
    extract::{Path, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::version::FirmwareVersion;
use serde::Deserialize;

use super::{
    access::{Services, Visit},
    analysis::Problem,
    kinds::{Mode, Step},
    screen,
    service::Wizards,
    warnings::Report,
};
use crate::{
    WebState,
    authz::CurrentUser,
    errors,
    overview::is_profile_id,
    page::{Localize, Shell},
    page_kit::{
        audit::Record as Audit,
        context::{Refusal, fragment_shell},
        respond::{self, Answer},
    },
};

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_target.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Migration id.
    id: String,
    /// A restore's fixed target, described.
    restore: Option<String>,
    /// Routers the user may migrate to.
    routers: Vec<(String, bool)>,
    /// Whether the source firmware must be typed in.
    ask_firmware: bool,
    /// The typed source firmware.
    firmware: String,
    /// The router select's error.
    router_error: String,
    /// The firmware field's error.
    firmware_error: String,
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

impl Panel {
    /// The panel of `visit`, with the chosen target's report when it can be read.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>) -> Self {
        let mut panel = Self::base(visit).await;
        if visit.record().target().is_some() {
            let locale = visit.services().user().locale();
            match visit.analysis().await {
                Ok(analysis) => {
                    let maps = visit.record().maps().cloned().unwrap_or_default();
                    panel.report = Some(Report::new(&analysis, &maps, locale));
                }
                Err(problem) => panel.explain(&problem, locale),
            }
        }
        panel
    }

    /// The panel of `visit` without reading the target.
    // cancel-safe: reads only.
    async fn base(visit: &Visit<'_>) -> Self {
        let services = visit.services();
        let locale = services.user().locale();
        let record = visit.record();
        let source_router = record.source().and_then(|source| source.router());
        let restore = (record.mode() == Mode::Restore).then(|| {
            let mut args = FluentArgs::new();
            args.set("router", record.target().unwrap_or_default().to_owned());
            tr(locale, keys::WEB_MIGRATE_TARGET_RESTORE, Some(&args))
        });
        let routers = match services.fleet().visible(services.user().role()).await {
            Ok(entries) => entries
                .into_iter()
                .map(|entry| entry.profile.id)
                .filter(|router| {
                    services.may_migrate(router) && Some(router.as_str()) != source_router
                })
                .map(|router| {
                    let selected = record.target() == Some(router.as_str());
                    (router, selected)
                })
                .collect(),
            Err(error) => {
                tracing::warn!(%error, "migration target: routers could not be listed");
                Vec::new()
            }
        };
        Self {
            shell: fragment_shell(locale),
            id: record.id().to_owned(),
            restore,
            routers,
            ask_firmware: record.source_firmware().is_some(),
            firmware: record.source_firmware().unwrap_or_default().to_owned(),
            router_error: String::new(),
            firmware_error: String::new(),
            problem: String::new(),
            report: None,
            acknowledged: record.acknowledged(),
            ack_error: String::new(),
        }
    }

    /// Whether the chosen target's firmware tier needs the acknowledgement and whether
    /// it cannot be migrated to at all; `None` when the target could not be read.
    pub(super) fn tier(&self) -> Option<(bool, bool)> {
        self.report
            .as_ref()
            .map(|report| (report.needs_ack(), report.unsupported()))
    }

    /// The panel with the acknowledgement's `error`.
    pub(super) fn refusing_ack(mut self, error: String) -> Self {
        self.ack_error = error;
        self
    }

    /// Shows why the target cannot be used.
    fn explain(&mut self, problem: &Problem, locale: Locale) {
        if *problem == Problem::FirmwareRequired {
            self.ask_firmware = true;
        }
        self.problem = problem_text(problem, locale);
    }
}

/// The router choice.
#[derive(Debug, Deserialize)]
pub(super) struct Choice {
    /// The target router.
    #[serde(default)]
    router: String,
    /// The source firmware, typed in when the source names none.
    #[serde(default)]
    firmware: String,
}

/// `POST /ui/migrate/{id}/target`: checks the target, reads its inventory and shows its
/// warnings.
///
/// # Errors
///
/// Answers the refusal of the migration, and the panel with its error (422): a router
/// the user may not migrate is refused before any request to it.
pub(super) async fn choose(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Extension(wizards): Extension<Arc<Wizards>>,
    user: CurrentUser,
    Form(choice): Form<Choice>,
) -> Result<Response, Answer> {
    let services = Services::of(&state, &user).map_err(Refusal::status)?;
    let mut visit = Visit::open(services, &wizards, &id)
        .await
        .map_err(Refusal::status)?;
    let session = visit.session();
    if visit.record().step() != Step::Target {
        return Ok(screen::moved(visit.record()));
    }
    let locale = user.locale();
    let router = choice.router.trim().to_owned();
    let firmware = choice.firmware.trim().to_owned();
    let fixed = visit.record().mode() == Mode::Restore;
    let same = visit
        .record()
        .source()
        .and_then(|source| source.router())
        .is_some_and(|source| source == router);
    let refused = if fixed && visit.record().target() != Some(router.as_str()) {
        Some(keys::WEB_MIGRATE_TARGET_ERROR_ROUTER)
    } else if !fixed && same {
        Some(keys::WEB_MIGRATE_TARGET_ERROR_SAME)
    } else if !services.permits(&router).await {
        Some(keys::WEB_MIGRATE_TARGET_ERROR_ROUTER)
    } else {
        None
    };
    if let Some(message) = refused {
        let audit = if is_profile_id(&router) {
            Audit::on_router("web.migrate_target", &router, id)
        } else {
            Audit::new("web.migrate_target", id)
        };
        audit.append(&state, &user, "forbidden").await;
        let mut panel = Panel::base(&visit).await;
        panel.router_error = tr(locale, message, None);
        return Err(respond::unprocessable(&panel).into());
    }
    if !firmware.is_empty() && FirmwareVersion::from_str(&firmware).is_err() {
        let mut panel = Panel::base(&visit).await;
        panel.ask_firmware = true;
        panel.firmware.clone_from(&firmware);
        panel.firmware_error = tr(locale, keys::WEB_MIGRATE_TARGET_ERROR_FIRMWARE, None);
        return Err(respond::unprocessable(&panel).into());
    }
    let typed = (!firmware.is_empty()).then_some(firmware);
    visit.record_mut().choose_target(router.clone(), typed);
    session.forget();
    if let Err(problem) = visit.analysis().await {
        let mut panel = Panel::base(&visit).await;
        panel.explain(&problem, locale);
        Audit::on_router("web.migrate_target", &router, id)
            .append(&state, &user, "refused")
            .await;
        return Err(respond::unprocessable(&panel).into());
    }
    if let Err(error) = visit.save() {
        return Err(errors::internal(&error, fragment_shell(locale)).into());
    }
    Audit::on_router("web.migrate_target", &router, id)
        .append(&state, &user, "chosen")
        .await;
    Ok(screen::moved(visit.record()))
}

/// The sentence explaining `problem`.
pub(crate) fn problem_text(problem: &Problem, locale: Locale) -> String {
    match problem {
        Problem::Source => tr(locale, keys::WEB_MIGRATE_PROBLEM_SOURCE, None),
        Problem::FirmwareRequired => tr(locale, keys::WEB_MIGRATE_PROBLEM_FIRMWARE_REQUIRED, None),
        Problem::FirmwareOlder { source, target } => {
            let mut args = FluentArgs::new();
            args.set("version", target.clone());
            args.set("value", source.clone());
            tr(
                locale,
                keys::WEB_MIGRATE_PROBLEM_FIRMWARE_OLDER,
                Some(&args),
            )
        }
        Problem::Unsupported => tr(locale, keys::WEB_MIGRATE_PROBLEM_UNSUPPORTED, None),
        Problem::Unreachable => tr(locale, keys::WEB_MIGRATE_PROBLEM_UNREACHABLE, None),
    }
}
