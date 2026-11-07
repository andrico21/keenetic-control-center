//! The wizard's record: every choice a migration has made so far, kept as
//! `<state>/migrations/<id>/wizard.json` so a reload (or a restart) resumes where it was.
//!
//! It holds router ids, object names, item indices, a URL, agreement texts and job facts,
//! never a secret: the source configuration and typed passwords are sealed in their own
//! files (`store`), and the plan is derived again from them whenever it is needed.

use alloc::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    kinds::{Inputs, Maps, Mode, Source, Step},
    run::{Finish, Run},
};

/// Version of the record format.
const SCHEMA: u32 = 1;

/// The record of one migration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    /// Version of this format.
    schema: u32,
    /// Migration id, also its directory name.
    id: String,
    /// The account that started it; nobody else opens it.
    owner: String,
    /// Unix time it started.
    created_at: u64,
    /// Migration or restore.
    mode: Mode,
    /// The step shown now.
    step: Step,
    /// Where the source configuration came from.
    #[serde(default)]
    source: Option<Source>,
    /// The source firmware typed in when the source names none.
    #[serde(default)]
    source_firmware: Option<String>,
    /// The router migrated to.
    #[serde(default)]
    target: Option<String>,
    /// Whether the documentation-based firmware tier was acknowledged.
    #[serde(default)]
    acknowledged: bool,
    /// The edited maps.
    #[serde(default)]
    maps: Option<Maps>,
    /// Source settings left out, by source index.
    #[serde(default)]
    excluded: BTreeSet<usize>,
    /// Conflicting settings that take the source's value, by source index.
    #[serde(default)]
    overwrite: BTreeSet<usize>,
    /// Components the user agreed to install first.
    #[serde(default)]
    components: BTreeSet<String>,
    /// The URL to reach the router at after the management changes.
    #[serde(default)]
    reconnect_url: Option<String>,
    /// Router agreements (`dpn`, `eula`) with the text the user accepted.
    #[serde(default)]
    agreements: BTreeMap<String, String>,
    /// Users whose new password is sealed beside the record.
    #[serde(default)]
    passwords: BTreeSet<String>,
    /// The id of the plan the preview showed.
    #[serde(default)]
    preview: Option<String>,
    /// The apply job.
    #[serde(default)]
    run: Option<Run>,
    /// How the migration finished, and when.
    #[serde(default)]
    finished: Option<(Finish, u64)>,
}

impl Record {
    /// A new migration at its first step.
    pub(super) const fn new(id: String, owner: String, created_at: u64) -> Self {
        Self {
            schema: SCHEMA,
            id,
            owner,
            created_at,
            mode: Mode::Migrate,
            step: Step::Source,
            source: None,
            source_firmware: None,
            target: None,
            acknowledged: false,
            maps: None,
            excluded: BTreeSet::new(),
            overwrite: BTreeSet::new(),
            components: BTreeSet::new(),
            reconnect_url: None,
            agreements: BTreeMap::new(),
            passwords: BTreeSet::new(),
            preview: None,
            run: None,
            finished: None,
        }
    }

    /// A restore of backup `name` of `router` onto `router`: source and target are fixed,
    /// so it starts at the target's warnings.
    pub(super) fn restore(
        id: String,
        owner: String,
        created_at: u64,
        (router, name): (String, String),
    ) -> Self {
        Self {
            mode: Mode::Restore,
            step: Step::Target,
            target: Some(router.clone()),
            source: Some(Source::Backup { router, name }),
            ..Self::new(id, owner, created_at)
        }
    }

    /// Whether this record is in the format this version reads.
    pub(super) const fn current(&self) -> bool {
        self.schema == SCHEMA
    }

    /// Migration id.
    pub(super) fn id(&self) -> &str {
        &self.id
    }

    /// The account that started it.
    pub(super) fn owner(&self) -> &str {
        &self.owner
    }

    /// Unix time it started.
    pub(super) const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Migration or restore.
    pub(super) const fn mode(&self) -> Mode {
        self.mode
    }

    /// The step shown now.
    pub(super) const fn step(&self) -> Step {
        self.step
    }

    /// Where the source configuration came from.
    pub(super) const fn source(&self) -> Option<&Source> {
        self.source.as_ref()
    }

    /// The source firmware typed in, when the source names none.
    pub(super) fn source_firmware(&self) -> Option<&str> {
        self.source_firmware.as_deref()
    }

    /// The router migrated to.
    pub(super) fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Whether the documentation-based firmware tier was acknowledged.
    pub(super) const fn acknowledged(&self) -> bool {
        self.acknowledged
    }

    /// The edited maps.
    pub(super) const fn maps(&self) -> Option<&Maps> {
        self.maps.as_ref()
    }

    /// Source settings left out, by source index.
    pub(super) const fn excluded(&self) -> &BTreeSet<usize> {
        &self.excluded
    }

    /// Conflicting settings that take the source's value, by source index.
    pub(super) const fn overwrite(&self) -> &BTreeSet<usize> {
        &self.overwrite
    }

    /// Components the user agreed to install first.
    pub(super) const fn components(&self) -> &BTreeSet<String> {
        &self.components
    }

    /// The URL to reach the router at after the management changes.
    pub(super) fn reconnect_url(&self) -> Option<&str> {
        self.reconnect_url.as_deref()
    }

    /// Router agreements with the text the user accepted.
    pub(super) const fn agreements(&self) -> &BTreeMap<String, String> {
        &self.agreements
    }

    /// Users whose new password is sealed beside the record.
    pub(super) const fn passwords(&self) -> &BTreeSet<String> {
        &self.passwords
    }

    /// Records one review choice for source setting `index`: left out, or (for a
    /// conflict) taking the source's value.
    pub(super) fn decide(&mut self, index: usize, excluded: bool, overwrite: bool) {
        let _: bool = if excluded {
            self.excluded.insert(index)
        } else {
            self.excluded.remove(&index)
        };
        let _: bool = if overwrite {
            self.overwrite.insert(index)
        } else {
            self.overwrite.remove(&index)
        };
    }

    /// Moves on from the review to the inputs.
    pub(super) const fn review_done(&mut self) {
        self.step = Step::Inputs;
    }

    /// Takes the inputs: consented components, the reconnect URL, accepted agreements
    /// and the users with a sealed password.
    pub(super) fn set_inputs(&mut self, inputs: Inputs) {
        (
            self.components,
            self.reconnect_url,
            self.agreements,
            self.passwords,
        ) = inputs.into_parts();
    }

    /// Moves on to the preview of the plan `plan`.
    pub(super) fn preview_ready(&mut self, plan: String) {
        self.preview = Some(plan);
        self.step = Step::Preview;
    }

    /// The id of the plan the preview showed.
    pub(super) fn preview(&self) -> Option<&str> {
        self.preview.as_deref()
    }

    /// The apply job.
    pub(super) const fn run(&self) -> Option<&Run> {
        self.run.as_ref()
    }

    /// The apply job, to record how it ended.
    pub(super) const fn run_mut(&mut self) -> Option<&mut Run> {
        self.run.as_mut()
    }

    /// How the migration finished, and when.
    pub(super) const fn finished(&self) -> Option<(Finish, u64)> {
        self.finished
    }

    /// Starts the apply `run`.
    pub(super) fn start_run(&mut self, run: Run) {
        self.run = Some(run);
        self.step = Step::Apply;
    }

    /// Shows the result of an apply that ended, or that no longer runs because kcc
    /// restarted (`interrupted`).
    pub(super) fn show_results(&mut self, interrupted: bool) -> bool {
        let ended = interrupted || self.run.as_ref().is_some_and(|run| run.ended().is_some());
        if ended && self.step == Step::Apply {
            self.step = Step::Results;
        }
        ended
    }

    /// Finishes the migration as `how` at `at`.
    pub(super) const fn finish(&mut self, how: Finish, at: u64) {
        self.finished = Some((how, at));
        self.step = Step::Report;
    }

    /// Plans again from `step` (the preview, or the maps after components were
    /// installed), forgetting an apply that changed nothing to keep.
    pub(super) fn plan_again(&mut self, step: Step) {
        self.run = None;
        if step == Step::Mapping {
            self.preview = None;
            self.components.clear();
        }
        self.step = step;
    }

    /// Every router the record names, for the scope check of each request.
    pub(super) fn routers(&self) -> Vec<&str> {
        self.source
            .as_ref()
            .and_then(Source::router)
            .into_iter()
            .chain(self.target.as_deref())
            .collect()
    }

    /// Takes `source` and moves on to the target; every later choice depended on the old
    /// source and starts over.
    pub(super) fn choose_source(&mut self, source: Source) {
        self.source = Some(source);
        self.source_firmware = None;
        self.target = None;
        self.forget_target_choices();
        self.step = Step::Target;
    }

    /// Takes `target` (and the source firmware typed in for it); the choices made for
    /// another target start over.
    pub(super) fn choose_target(&mut self, target: String, firmware: Option<String>) {
        if firmware.is_some() {
            self.source_firmware = firmware;
        }
        self.target = Some(target);
        self.forget_target_choices();
        self.step = Step::Target;
    }

    /// Moves on to the maps, with the documentation-based tier acknowledged or not needed.
    pub(super) const fn confirm_target(&mut self, acknowledged: bool) {
        self.acknowledged = acknowledged;
        self.step = Step::Mapping;
    }

    /// Takes the edited maps and moves on to the review.
    pub(super) fn set_maps(&mut self, maps: Maps) {
        self.maps = Some(maps);
        self.step = Step::Review;
    }

    /// Shows `step` again, when it comes before the current one and is still editable:
    /// nothing after the preview goes back, and a restore's source is fixed.
    pub(super) fn go_back(&mut self, step: Step) -> bool {
        let fixed_source = self.mode == Mode::Restore && step == Step::Source;
        let allowed = step < self.step && self.step <= Step::Preview && !fixed_source;
        if allowed {
            self.step = step;
        }
        allowed
    }

    /// The step Back shows: the one before the current, while choices can still change.
    pub(super) fn previous(&self) -> Option<Step> {
        let index = Step::ALL.iter().position(|step| *step == self.step)?;
        let previous = *Step::ALL.get(index.checked_sub(1)?)?;
        let fixed_source = self.mode == Mode::Restore && previous == Step::Source;
        (self.step <= Step::Preview && !fixed_source).then_some(previous)
    }

    /// Clears what was chosen for one target.
    fn forget_target_choices(&mut self) {
        self.acknowledged = false;
        self.maps = None;
        self.excluded.clear();
        self.overwrite.clear();
        self.components.clear();
        self.reconnect_url = None;
        self.agreements.clear();
        self.passwords.clear();
        self.preview = None;
    }
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
