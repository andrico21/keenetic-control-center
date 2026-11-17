//! What a run's choices make of its settings: the engine's preset plan of every item
//! (what the review shows), and the protected apply request of the items kept.
//!
//! A left-out item is dropped from the reviewed plan before it becomes a request, so a
//! left-out removal keeps the router's setting and a left-out setting is never sent.

use alloc::{collections::BTreeMap, sync::Arc};

use kcc_app::audit::{Actor, ActorKind};
use kcc_migrate::{
    apply::ApplyRequest,
    inventory::TargetInventory,
    maps::InterfaceMap,
    planner::{Choices, MigrationMaps},
    presets::{
        apply::{PresetApplyError, PresetApplyOptions, PresetApplyRequest, request},
        model::Preset,
        plan::{PresetInput, PresetPlan, PresetPlanError, plan},
    },
};
use secrecy::SecretString;

use super::{
    access::{PresetRun as _, Visit},
    record::Record,
};
use crate::{
    WebState,
    wizard::{analysis::Problem, flow::Flow as _, names::map_of, services::Services},
};

/// Why a run's plan cannot become an apply request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Refused {
    /// The engine refused to plan: firmware or acknowledgement.
    Plan(PresetPlanError),
    /// Items still need input, or the role may no longer use a router.
    Apply(PresetApplyError),
}

/// What a run plans with: its settings, the target's inventory and the typed passwords.
pub(super) struct Basis {
    /// The settings, with their secrets.
    preset: Preset,
    /// The target's inventory.
    inventory: Arc<TargetInventory>,
    /// Typed passwords by user name.
    passwords: BTreeMap<String, SecretString>,
}

impl Basis {
    /// Reads the run's settings, the target's inventory and the typed passwords.
    ///
    /// # Errors
    ///
    /// Returns why the settings or the target cannot be used.
    // cancel-safe: reads only.
    pub(super) async fn of(visit: &Visit<'_>) -> Result<Self, Problem> {
        let preset = visit.preset().await?;
        let inventory = visit.inventory(&preset).await?;
        let passwords = visit.passwords().await.map_err(|error| {
            tracing::error!(%error, "preset run passwords could not be opened");
            Problem::Source
        })?;
        Ok(Self {
            preset,
            inventory,
            passwords,
        })
    }

    /// The settings.
    pub(super) const fn preset(&self) -> &Preset {
        &self.preset
    }

    /// Replaces the typed passwords.
    pub(super) fn set_passwords(&mut self, passwords: BTreeMap<String, SecretString>) {
        self.passwords = passwords;
    }

    /// The users whose password `record`'s kept settings need: their hashes are bound
    /// to the source's realm, typed or not.
    ///
    /// # Errors
    ///
    /// Returns the engine's refusal.
    pub(super) fn users(&self, record: &Record) -> Result<Vec<String>, PresetPlanError> {
        let planned = self.plan_with(record, &BTreeMap::new())?;
        let mut users = planned
            .items
            .iter()
            .filter(|item| !record.excluded().contains(&item.index))
            .filter_map(|item| match &item.needed_input {
                Some(PresetInput::RouterUserPassword { user }) => Some(user.clone()),
                Some(PresetInput::Mapping { source: _ }) | None => None,
            })
            .collect::<Vec<_>>();
        users.sort();
        users.dedup();
        Ok(users)
    }

    /// The plan of every item under `record`'s choices.
    ///
    /// # Errors
    ///
    /// Returns the engine's refusal.
    pub(super) fn plan(&self, record: &Record) -> Result<PresetPlan, PresetPlanError> {
        self.plan_with(record, &self.passwords)
    }

    /// The plan of every item under `record`'s choices with `passwords`.
    ///
    /// # Errors
    ///
    /// Returns the engine's refusal.
    fn plan_with(
        &self,
        record: &Record,
        passwords: &BTreeMap<String, SecretString>,
    ) -> Result<PresetPlan, PresetPlanError> {
        let mut maps = MigrationMaps::default();
        maps.interfaces = map_of::<InterfaceMap, _>(
            record
                .interfaces()
                .iter()
                .map(|(source, target)| (source.clone(), Some(target.clone()))),
        );
        maps.policies = record.policies().clone();
        let mut choices = Choices::default();
        choices.new_passwords = passwords.clone();
        if record.acknowledged() {
            choices = choices.with_documentation_tier_acknowledgement();
        }
        plan(
            &self.preset,
            &self.inventory,
            record.mode().engine(),
            &maps,
            &choices,
        )
    }

    /// The plan of the items `record` keeps.
    ///
    /// # Errors
    ///
    /// Returns the engine's refusal.
    pub(super) fn kept(&self, record: &Record) -> Result<PresetPlan, PresetPlanError> {
        let mut planned = self.plan(record)?;
        planned
            .items
            .retain(|item| !record.excluded().contains(&item.index));
        Ok(planned)
    }

    /// The engine's apply request of the items `record` keeps, as `services`' user.
    ///
    /// # Errors
    ///
    /// Returns the engine's refusal.
    pub(super) fn request(
        self,
        record: &Record,
        state: &WebState,
        services: Services<'_>,
    ) -> Result<ApplyRequest, Refused> {
        let kept = self.kept(record).map_err(Refused::Plan)?;
        let user = services.user();
        let mut input = PresetApplyRequest::new(
            Arc::clone(services.fleet().workflow()),
            state.audit().clone(),
            Actor::new(ActorKind::Web, user.username().to_owned()),
            user.role().clone(),
            record.target().unwrap_or_default().to_owned(),
            self.preset,
            kept,
            (*self.inventory).clone(),
        );
        if record.keep_keys() {
            input.options = PresetApplyOptions::default().keep_wireguard_keys();
        }
        let mut built = request(input).map_err(Refused::Apply)?;
        built.options.locale = user.locale();
        Ok(built)
    }
}

/// The problem a planning refusal means: the target step already refuses older firmware
/// with its versions and asks for the tier acknowledgement, so a refusal here means the
/// target changed meanwhile.
pub(super) const fn plan_problem(error: &PresetPlanError) -> Problem {
    match error {
        PresetPlanError::InvalidSourceFirmware => Problem::Source,
        PresetPlanError::TargetFirmwareOlder
        | PresetPlanError::UnsupportedFirmware
        | PresetPlanError::DocumentationTierAcknowledgementRequired
        | _ => Problem::Unsupported,
    }
}
