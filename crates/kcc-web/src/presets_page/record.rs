//! A preset run's record: every choice it made so far, kept as
//! `<state>/migrations/<id>/preset.json` beside the migration wizard's runs, so a reload
//! (or a restart) resumes where it was.
//!
//! It holds router ids, group ids, object names, item indices and job facts, never a
//! secret: the copied settings and typed passwords are sealed in their own files, and
//! the plan is derived again from them whenever it is needed. Public WireGuard keys are
//! not secret.

use alloc::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::steps::{Finish, Mode, Origin, Step};
use crate::migrate_wizard::run::Run;

/// Version of the record format.
const SCHEMA: u32 = 1;

/// The record's file name in the run's directory.
pub(super) const FILE: &str = "preset.json";

/// The record of one run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    /// Version of this format.
    schema: u32,
    /// Run id, also its directory name.
    id: String,
    /// The account that started it; nobody else opens it.
    owner: String,
    /// Unix time it started.
    created_at: u64,
    /// A saved preset or a copy.
    origin: Origin,
    /// The step shown now.
    step: Step,
    /// The router the settings come from, for the scope check of every request.
    #[serde(default)]
    source_router: Option<String>,
    /// The router the settings go to.
    #[serde(default)]
    target: Option<String>,
    /// Whether the documentation-based firmware tier was acknowledged.
    #[serde(default)]
    acknowledged: bool,
    /// Merge or Mirror.
    #[serde(default)]
    mode: Mode,
    /// Whether captured WireGuard private keys are copied instead of made anew.
    #[serde(default)]
    keep_keys: bool,
    /// Interface names on the router, by name in the settings.
    #[serde(default)]
    interfaces: BTreeMap<String, String>,
    /// Policy names on the router, by name in the settings.
    #[serde(default)]
    policies: BTreeMap<String, String>,
    /// Plan items left out, by index.
    #[serde(default)]
    excluded: BTreeSet<usize>,
    /// Users whose password is sealed beside the record.
    #[serde(default)]
    passwords: BTreeSet<String>,
    /// The id of the plan the preview showed.
    #[serde(default)]
    preview: Option<String>,
    /// The apply job.
    #[serde(default)]
    run: Option<Run>,
    /// New WireGuard public keys the apply read back: interface and key.
    #[serde(default)]
    keys: Vec<(String, String)>,
    /// Interfaces whose captured private key was copied.
    #[serde(default)]
    kept_keys: Vec<String>,
    /// How the run finished, and when.
    #[serde(default)]
    finished: Option<(Finish, u64)>,
}

impl Record {
    /// A new run of `origin` for `owner`, started at `created_at`: a preset's run starts
    /// at the target (its source is fixed), a copy at its source.
    pub(super) fn new(
        (id, owner): (String, String),
        created_at: u64,
        origin: Origin,
        source_router: Option<String>,
    ) -> Self {
        let step = match origin {
            Origin::Preset { id: _, name: _ } => Step::Target,
            Origin::Copy => Step::Source,
        };
        Self {
            schema: SCHEMA,
            id,
            owner,
            created_at,
            origin,
            step,
            source_router,
            target: None,
            acknowledged: false,
            mode: Mode::Merge,
            keep_keys: false,
            interfaces: BTreeMap::new(),
            policies: BTreeMap::new(),
            excluded: BTreeSet::new(),
            passwords: BTreeSet::new(),
            preview: None,
            run: None,
            keys: Vec::new(),
            kept_keys: Vec::new(),
            finished: None,
        }
    }

    /// Whether this record is in the format this version reads.
    pub(super) const fn current(&self) -> bool {
        self.schema == SCHEMA
    }

    /// Run id.
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

    /// A saved preset or a copy.
    pub(super) const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The step shown now.
    pub(super) const fn step(&self) -> Step {
        self.step
    }

    /// The router the settings come from.
    pub(super) fn source_router(&self) -> Option<&str> {
        self.source_router.as_deref()
    }

    /// The router the settings go to.
    pub(super) fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Whether the documentation-based firmware tier was acknowledged.
    pub(super) const fn acknowledged(&self) -> bool {
        self.acknowledged
    }

    /// Merge or Mirror.
    pub(super) const fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether captured WireGuard private keys are copied.
    pub(super) const fn keep_keys(&self) -> bool {
        self.keep_keys
    }

    /// Interface names on the router, by name in the settings.
    pub(super) const fn interfaces(&self) -> &BTreeMap<String, String> {
        &self.interfaces
    }

    /// Policy names on the router, by name in the settings.
    pub(super) const fn policies(&self) -> &BTreeMap<String, String> {
        &self.policies
    }

    /// Plan items left out, by index.
    pub(super) const fn excluded(&self) -> &BTreeSet<usize> {
        &self.excluded
    }

    /// Users whose password is sealed beside the record.
    pub(super) const fn passwords(&self) -> &BTreeSet<String> {
        &self.passwords
    }

    /// The id of the plan the preview showed.
    pub(super) fn preview(&self) -> Option<&str> {
        self.preview.as_deref()
    }

    /// The apply job.
    pub(super) const fn run(&self) -> Option<&Run> {
        self.run.as_ref()
    }

    /// New WireGuard public keys: interface and key.
    pub(super) fn keys(&self) -> &[(String, String)] {
        &self.keys
    }

    /// Interfaces whose captured private key was copied.
    pub(super) fn kept_keys(&self) -> &[String] {
        &self.kept_keys
    }

    /// How the run finished, and when.
    pub(super) const fn finished(&self) -> Option<(Finish, u64)> {
        self.finished
    }

    /// Every router the record names, for the scope check of each request.
    pub(super) fn routers(&self) -> Vec<&str> {
        self.source_router
            .as_deref()
            .into_iter()
            .chain(self.target.as_deref())
            .collect()
    }

    /// Takes the copy's source router and moves on to the target.
    pub(super) fn choose_source(&mut self, router: String) {
        self.source_router = Some(router);
        self.target = None;
        self.forget_target_choices();
        self.step = Step::Target;
    }

    /// Takes `target`; the choices made for another target start over.
    pub(super) fn choose_target(&mut self, target: String) {
        self.target = Some(target);
        self.forget_target_choices();
        self.step = Step::Target;
    }

    /// Moves on to the options, the documentation-based tier acknowledged or not needed.
    pub(super) const fn confirm_target(&mut self, acknowledged: bool) {
        self.acknowledged = acknowledged;
        self.step = Step::Options;
    }

    /// Takes the options and moves on to the review.
    pub(super) fn set_options(
        &mut self,
        (mode, keep_keys): (Mode, bool),
        (interfaces, policies): (BTreeMap<String, String>, BTreeMap<String, String>),
    ) {
        self.mode = mode;
        self.keep_keys = keep_keys;
        self.interfaces = interfaces;
        self.policies = policies;
        self.excluded.clear();
        self.preview = None;
        self.step = Step::Review;
    }

    /// Leaves item `index` out, or takes it back in.
    pub(super) fn include(&mut self, index: usize, included: bool) {
        let _: bool = if included {
            self.excluded.remove(&index)
        } else {
            self.excluded.insert(index)
        };
    }

    /// Moves on from the review to the inputs.
    pub(super) const fn review_done(&mut self) {
        self.step = Step::Inputs;
    }

    /// Takes the users with a sealed password.
    pub(super) fn set_passwords(&mut self, users: BTreeSet<String>) {
        self.passwords = users;
    }

    /// Moves on to the preview of the plan `plan`.
    pub(super) fn preview_ready(&mut self, plan: String) {
        self.preview = Some(plan);
        self.step = Step::Preview;
    }

    /// The apply job, to record how it ended.
    pub(super) const fn run_mut(&mut self) -> Option<&mut Run> {
        self.run.as_mut()
    }

    /// Records the WireGuard keys the apply made, and those it copied.
    pub(super) fn set_keys(&mut self, keys: Vec<(String, String)>, kept: Vec<String>) {
        self.keys = keys;
        self.kept_keys = kept;
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

    /// Finishes the run as `how` at `at`.
    pub(super) const fn finish(&mut self, how: Finish, at: u64) {
        self.finished = Some((how, at));
        self.step = Step::Report;
    }

    /// Plans again from the preview, forgetting an apply that changed nothing.
    pub(super) fn plan_again(&mut self) {
        self.run = None;
        self.step = Step::Preview;
    }

    /// Shows `step` again, when it comes before the current one and is still editable:
    /// nothing after the preview goes back, and a preset's source is fixed.
    pub(super) fn go_back(&mut self, step: Step) -> bool {
        let fixed = self.fixed_source() && step == Step::Source;
        let allowed = step < self.step && self.step <= Step::Preview && !fixed;
        if allowed {
            self.step = step;
        }
        allowed
    }

    /// The step Back shows: the one before the current, while choices can still change.
    pub(super) fn previous(&self) -> Option<Step> {
        let index = Step::ALL.iter().position(|step| *step == self.step)?;
        let previous = *Step::ALL.get(index.checked_sub(1)?)?;
        let fixed = self.fixed_source() && previous == Step::Source;
        (self.step <= Step::Preview && !fixed).then_some(previous)
    }

    /// Whether the source is fixed: a saved preset's.
    const fn fixed_source(&self) -> bool {
        matches!(self.origin, Origin::Preset { id: _, name: _ })
    }

    /// Clears what was chosen for one target.
    fn forget_target_choices(&mut self) {
        self.acknowledged = false;
        self.interfaces.clear();
        self.policies.clear();
        self.excluded.clear();
        self.passwords.clear();
        self.preview = None;
    }
}
