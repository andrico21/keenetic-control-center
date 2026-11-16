//! What makes a wizard (its steps, its record and its files) and the step machine every
//! wizard's record moves through.
//!
//! Each wizard's record keeps its own on-disk shape: a flat JSON object that refuses
//! unknown fields, with its fields in an order of its own. So the record implements
//! [`Flow`] by naming the fields every record has, and lends the four the machine
//! changes as [`Moves`]; the machine itself is written once, here.

use axum::response::Response;
use kcc_i18n::{bundle::MessageKey, locale::Locale};
use serde::{Serialize, de::DeserializeOwned};

use super::{run::Run, visit::Visit};
use crate::{WebState, nav::Section, page::Shell};

/// Version of every wizard's record format.
pub(crate) const SCHEMA: u32 = 1;

/// The fields of a record the step machine changes.
pub(crate) struct Moves<'record, F>
where
    F: Flow,
{
    /// The step shown now.
    step: &'record mut F::Step,
    /// The id of the plan the preview showed.
    preview: &'record mut Option<String>,
    /// The apply job.
    run: &'record mut Option<Run>,
    /// How the run finished, and when.
    finished: &'record mut Option<(F::Finish, u64)>,
}

impl<'record, F> Moves<'record, F>
where
    F: Flow,
{
    /// The record's step, preview, apply job and finish.
    pub(crate) const fn new(
        step: &'record mut F::Step,
        preview: &'record mut Option<String>,
        run: &'record mut Option<Run>,
        finished: &'record mut Option<(F::Finish, u64)>,
    ) -> Self {
        Self {
            step,
            preview,
            run,
            finished,
        }
    }
}

/// One step of a wizard: its place, and its names in forms and in the step list.
pub(crate) trait Stage: Copy + Ord + Send + Sync + DeserializeOwned + 'static {
    /// Every step in order.
    const ALL: [Self; 9];

    /// The step's name in forms, as serialized.
    fn slug(self) -> &'static str;

    /// The step's name in the step list.
    fn label(self) -> MessageKey;

    /// The step's number, 1 to 9.
    fn number(self) -> u32 {
        Self::ALL
            .iter()
            .position(|step| *step == self)
            .and_then(|index| u32::try_from(index).ok())
            .map_or(1, |index| index.saturating_add(1))
    }
}

/// One wizard: its steps, its record, the file it is kept in and its pages.
///
/// Implemented by the wizard's record, which stays the on-disk format.
pub(crate) trait Flow: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// One step of the wizard.
    type Step: Stage;
    /// How a run finished.
    type Finish: Copy + Send + Sync + 'static;
    /// What a run works on, read from the routers once and kept while it is open.
    type Analysis: Send + Sync + 'static;
    /// The query of the run's page.
    type View: DeserializeOwned + Send + Sync + 'static;

    /// The ordered commands; nothing after it goes back.
    const PREVIEW: Self::Step;
    /// The apply job, followed live.
    const APPLY: Self::Step;
    /// The verified result and the choice how to finish.
    const RESULTS: Self::Step;
    /// The report of the finished run.
    const REPORT: Self::Step;
    /// The record's file name in the run's directory.
    const FILE: &'static str;
    /// Where the run pages are: run `id`'s is `{PREFIX}/{id}`.
    const PREFIX: &'static str;
    /// The page listing the wizard's runs.
    const LIST: &'static str;
    /// The link to that page.
    const ALL: MessageKey;
    /// The step list's name.
    const STEPS_LABEL: MessageKey;
    /// The navigation section of the run's pages.
    const SECTION: Section;
    /// How a run that ended without a recorded finish reads.
    const CLOSED: Self::Finish;
    /// The audit action of Stop.
    const STOP: &'static str;
    /// The audit action of a request on a run, recorded when it is refused.
    const RUN: &'static str;

    /// The sentence saying how a run finished.
    fn finish_text(how: Self::Finish) -> MessageKey;

    /// Whether a run that finished `how` kept its changes.
    fn succeeded(how: Self::Finish) -> bool;

    /// The title of the run's page.
    fn title(&self) -> MessageKey;

    /// What the run works on, as far as chosen: label and value.
    fn summary(&self, locale: Locale) -> Vec<(String, String)>;

    /// The page of the run `visit` opened, at its current step, in `shell`, for the
    /// page's query and the Web services.
    fn show(
        visit: &Visit<'_, Self>,
        shell: Shell,
        request: (&Self::View, &WebState),
    ) -> impl Future<Output = Response> + Send;

    /// Version of the record's format.
    fn schema(&self) -> u32;

    /// Run id, also its directory name.
    fn id(&self) -> &str;

    /// The account that started it; nobody else opens it.
    fn owner(&self) -> &str;

    /// Unix time it started.
    fn created_at(&self) -> u64;

    /// The step shown now.
    fn step(&self) -> Self::Step;

    /// The router the run applies to, once chosen.
    fn target(&self) -> Option<&str>;

    /// The id of the plan the preview showed.
    fn preview(&self) -> Option<&str>;

    /// The apply job.
    fn run(&self) -> Option<&Run>;

    /// How the run finished, and when.
    fn finished(&self) -> Option<(Self::Finish, u64)>;

    /// The fields the step machine changes.
    fn moves(&mut self) -> Moves<'_, Self>;

    /// Whether `step` is fixed in this run and never shows again: a restore's or a saved
    /// preset's source.
    fn fixed(&self, step: Self::Step) -> bool;

    /// Every router the record names, for the scope check of each request.
    fn routers(&self) -> Vec<&str>;

    /// Whether this record is in the format this version reads.
    fn current(&self) -> bool {
        self.schema() == SCHEMA
    }

    /// The apply job, to record how it ended.
    fn run_mut(&mut self) -> Option<&mut Run> {
        let Moves {
            run,
            step: _,
            preview: _,
            finished: _,
        } = self.moves();
        run.as_mut()
    }

    /// Moves on to the preview of the plan `plan`.
    fn preview_ready(&mut self, plan: String) {
        let moves = self.moves();
        *moves.preview = Some(plan);
        *moves.step = Self::PREVIEW;
    }

    /// Starts the apply `run`.
    fn start_run(&mut self, run: Run) {
        let moves = self.moves();
        *moves.run = Some(run);
        *moves.step = Self::APPLY;
    }

    /// Shows the result of an apply that ended, or that no longer runs because kcc
    /// restarted (`interrupted`).
    fn show_results(&mut self, interrupted: bool) -> bool {
        let moves = self.moves();
        let ended = interrupted || moves.run.as_ref().is_some_and(|run| run.ended().is_some());
        if ended && *moves.step == Self::APPLY {
            *moves.step = Self::RESULTS;
        }
        ended
    }

    /// Finishes the run as `how` at `at`.
    fn finish(&mut self, how: Self::Finish, at: u64) {
        let moves = self.moves();
        *moves.finished = Some((how, at));
        *moves.step = Self::REPORT;
    }

    /// Shows `step` again, when it comes before the current one and is still editable:
    /// nothing after the preview goes back, and a fixed step never shows again.
    fn go_back(&mut self, step: Self::Step) -> bool {
        let current = self.step();
        let allowed = step < current && current <= Self::PREVIEW && !self.fixed(step);
        if allowed {
            *self.moves().step = step;
        }
        allowed
    }

    /// The step Back shows: the one before the current, while choices can still change.
    fn previous(&self) -> Option<Self::Step> {
        let current = self.step();
        let index = Self::Step::ALL.iter().position(|step| *step == current)?;
        let previous = *Self::Step::ALL.get(index.checked_sub(1)?)?;
        (current <= Self::PREVIEW && !self.fixed(previous)).then_some(previous)
    }
}
