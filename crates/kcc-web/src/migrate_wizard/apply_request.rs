//! The engine's apply request of a migration.
//!
//! The plan is built again from a fresh read of the target (refused when it is not the
//! plan the preview showed), the source is given as the engine reads it, and the options
//! follow the user's choices.

use alloc::{collections::BTreeMap, sync::Arc};
use core::str::FromStr as _;

use kcc_app::audit::{Actor, ActorKind};
use kcc_migrate::{
    apply::{ApplyRequest, ApplySource},
    planner::PlannedLine,
    report::MigrationReport,
};
use kcc_rci::{SecretBytes, version::FirmwareVersion};
use secrecy::ExposeSecret as _;

use super::{
    access::{Migration as _, Visit},
    kinds::Source,
    plan::{Built, Classified},
};
use crate::{
    WebState,
    wizard::{flow::Flow as _, store::Sealed},
};

/// Why the apply cannot start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Refused {
    /// The source or the target cannot be read now.
    Unreadable,
    /// The plan built now (its id given) differs from the one the preview showed.
    Changed(String),
    /// The migration's state cannot be read or the plan's files written.
    Broken,
}

/// An apply ready to start.
pub(super) struct Prepared {
    /// The engine's request.
    request: ApplyRequest,
    /// For each planned setting, its source line and redacted text.
    texts: BTreeMap<usize, (usize, String)>,
    /// The redacted report of the plan, as JSON.
    report: String,
    /// The plan's redacted form.
    plan: String,
    /// The commands the plan sends.
    commands: usize,
}

impl Prepared {
    /// Builds the apply of `visit` for `state`'s audit log.
    ///
    /// # Errors
    ///
    /// Returns why the apply cannot start.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>, state: &WebState) -> Result<Self, Refused> {
        let services = visit.services();
        let fleet = services.fleet();
        let record = visit.record();
        let user = services.user();
        visit.session().forget();
        let analysis = visit
            .analysis()
            .await
            .map_err(|_problem| Refused::Unreadable)?;
        let passwords = visit.passwords().map_err(|_error| Refused::Broken)?;
        let classified =
            Classified::new(&analysis, record, &passwords).map_err(|_error| Refused::Broken)?;
        let built = Built::new(&analysis, record, &passwords).map_err(|_error| Refused::Broken)?;
        if record.preview() != Some(built.plan().plan_id.as_str()) {
            return Err(Refused::Changed(built.plan().plan_id.clone()));
        }
        let mut texts = BTreeMap::new();
        let phases = &built.plan().phases;
        for line in phases
            .additive
            .iter()
            .chain(&phases.prune)
            .chain(&phases.management)
        {
            drop(texts.insert(line.source_index, text(&built, &classified, line)));
        }
        let report = MigrationReport::from_plan(built.plan(), user.locale())
            .to_json()
            .map_err(|_error| Refused::Broken)?;
        let plan = serde_json::to_string_pretty(built.plan()).map_err(|_error| Refused::Broken)?;
        let target = record.target().ok_or(Refused::Broken)?.to_owned();
        let source = match record.source().ok_or(Refused::Broken)? {
            Source::Router { router } => ApplySource::LiveRouter {
                id: router.clone(),
                client: fleet
                    .registry()
                    .client(router)
                    .await
                    .map_err(|_error| Refused::Unreadable)?,
            },
            Source::Backup { router, name } => ApplySource::Backup {
                store: Arc::clone(fleet.workflow().backups()),
                router: router.clone(),
                name: name.clone(),
            },
            Source::File { name: _ } => {
                let text = services
                    .store()
                    .open(services.key(), record.id(), Sealed::Source)
                    .map_err(|_error| Refused::Broken)?
                    .ok_or(Refused::Broken)?;
                ApplySource::File(SecretBytes::from(text.expose_secret().as_bytes().to_vec()))
            }
        };
        let login = fleet
            .registry()
            .get(&target)
            .map_err(|_error| Refused::Unreadable)?
            .profile
            .login;
        let commands = texts.len();
        let actor = Actor::new(ActorKind::Web, user.username().to_owned());
        let mut request = ApplyRequest::new(
            Arc::clone(fleet.workflow()),
            state.audit().clone(),
            actor,
            user.role().clone(),
            target,
            built.into_plan(),
            source,
        );
        request.options.install_components = record.components().iter().cloned().collect();
        request.options.ack_documentation_tier = record.acknowledged();
        request.options.agreements = record.agreements().clone();
        request.options.management_password = passwords.get(&login).cloned();
        request.options.source_firmware = record
            .source_firmware()
            .and_then(|typed| FirmwareVersion::from_str(typed).ok());
        request.options.locale = user.locale();
        Ok(Self {
            request,
            texts,
            report,
            plan,
            commands,
        })
    }

    /// The fail-safe timer's length, in seconds.
    pub(super) const fn safety_seconds(&self) -> u64 {
        self.request.options.safety_seconds
    }

    /// The commands the plan sends.
    pub(super) const fn commands(&self) -> usize {
        self.commands
    }

    /// The request, the texts, the report and the plan.
    pub(super) fn into_parts(
        self,
    ) -> (
        ApplyRequest,
        BTreeMap<usize, (usize, String)>,
        String,
        String,
    ) {
        (self.request, self.texts, self.report, self.plan)
    }
}

/// The source line and redacted text of planned `line`.
fn text(built: &Built, classified: &Classified, line: &PlannedLine) -> (usize, String) {
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
}
