//! A preset run's record: every choice it made so far, kept as
//! `<state>/migrations/<id>/preset.json` beside the migration wizard's runs, so a reload
//! (or a restart) resumes where it was.
//!
//! It holds router ids, group ids, object names, item indices and job facts, never a
//! secret: the copied settings and typed passwords are sealed in their own files, and
//! the plan is derived again from them whenever it is needed. Public WireGuard keys are
//! not secret.

use alloc::collections::{BTreeMap, BTreeSet};

use axum::response::Response;
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};
use serde::{Deserialize, Serialize};

use super::{
    resume,
    review::View,
    steps::{Finish, Mode, Origin, Step},
    summary,
};
use crate::{
    WebState,
    nav::Section,
    page::Shell,
    wizard::{
        flow::{Flow, Moves, SCHEMA},
        run::Run,
        visit::Visit,
    },
};

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

    /// A saved preset or a copy.
    pub(super) const fn origin(&self) -> &Origin {
        &self.origin
    }

    /// The router the settings come from.
    pub(super) fn source_router(&self) -> Option<&str> {
        self.source_router.as_deref()
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

    /// New WireGuard public keys: interface and key.
    pub(super) fn keys(&self) -> &[(String, String)] {
        &self.keys
    }

    /// Interfaces whose captured private key was copied.
    pub(super) fn kept_keys(&self) -> &[String] {
        &self.kept_keys
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

    /// Records the WireGuard keys the apply made, and those it copied.
    pub(super) fn set_keys(&mut self, keys: Vec<(String, String)>, kept: Vec<String>) {
        self.keys = keys;
        self.kept_keys = kept;
    }

    /// Plans again from the preview, forgetting an apply that changed nothing.
    pub(super) fn plan_again(&mut self) {
        self.run = None;
        self.step = Step::Preview;
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

impl Flow for Record {
    type Step = Step;
    type Finish = Finish;
    type Analysis = ();
    type View = View;

    const PREVIEW: Step = Step::Preview;
    const APPLY: Step = Step::Apply;
    const RESULTS: Step = Step::Results;
    const REPORT: Step = Step::Report;
    const FILE: &'static str = FILE;
    const PREFIX: &'static str = "/ui/presets/runs";
    const LIST: &'static str = "/ui/presets";
    const ALL: MessageKey = keys::WEB_PRESETS_ALL;
    const STEPS_LABEL: MessageKey = keys::WEB_PRESETS_STEPS_LABEL;
    const SECTION: Section = Section::Presets;
    const CLOSED: Finish = Finish::Closed;
    const STOP: &'static str = "web.preset_stop";
    const RUN: &'static str = "web.preset_run";

    fn finish_text(how: Finish) -> MessageKey {
        how.text()
    }

    fn succeeded(how: Finish) -> bool {
        match how {
            Finish::KeptUnsaved | Finish::Saved => true,
            Finish::RolledBack
            | Finish::RolledBackByRouter
            | Finish::RollbackRestarting
            | Finish::Closed => false,
        }
    }

    fn title(&self) -> MessageKey {
        summary::title(&self.origin)
    }

    fn summary(&self, locale: Locale) -> Vec<(String, String)> {
        summary::summary(self, locale)
    }

    fn show(
        visit: &Visit<'_, Self>,
        shell: Shell,
        request: (&View, &WebState),
    ) -> impl Future<Output = Response> + Send {
        resume::show(visit, shell, request)
    }

    record_fields!();

    fn fixed(&self, step: Step) -> bool {
        matches!(self.origin, Origin::Preset { id: _, name: _ }) && step == Step::Source
    }

    fn routers(&self) -> Vec<&str> {
        self.source_router
            .as_deref()
            .into_iter()
            .chain(self.target.as_deref())
            .collect()
    }
}
