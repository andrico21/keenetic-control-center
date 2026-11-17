//! Step 4: every source setting and what happens to it.
//!
//! Filtered by fate and paged by 50; settings that can be left out have Migrate,
//! settings whose value differs from the router's have the choice of value. Choices save
//! as they change.

use askama::Template;
use kcc_i18n::{bundle::tr, keys};
use serde::Deserialize;

use super::{
    access::{Migration as _, Visit},
    plan::Classified,
    reasons::{Fate, Resolution, reason},
    record::Record,
    target::problem_text,
};
use crate::{
    page::{Localize as _, Shell},
    page_kit::context::fragment_shell,
    table::pager::Pager,
    wizard::{
        filters::{Filter, filters},
        flow::Flow as _,
        screen,
    },
};

/// The review's filter and page.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct View {
    /// The fate shown; all when absent.
    #[serde(default)]
    show: Option<String>,
    /// The page shown, from 1.
    #[serde(default)]
    page: Option<usize>,
}

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/migrate_review.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Migration id.
    id: String,
    /// The filter links.
    filters: Vec<Filter>,
    /// The shown page of settings.
    rows: Vec<Row>,
    /// The page links.
    pager: Pager,
    /// Why Continue was refused.
    error: String,
    /// Why the settings cannot be shown.
    problem: String,
}

localized!(Panel);

/// The control of a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Control {
    /// The setting cannot be left out or changed.
    None,
    /// Migrate it or leave it out; whether it is migrated.
    Include(bool),
    /// Which value stays.
    Resolve(Resolution),
}

/// One setting.
struct Row {
    /// Its source index, the form's value.
    index: usize,
    /// Its line in the source configuration.
    line: usize,
    /// Its fate's slug.
    fate: &'static str,
    /// Its fate.
    label: String,
    /// Why.
    reason: String,
    /// The source's setting, redacted.
    before: String,
    /// What the router gets, redacted; empty when nothing.
    after: String,
    /// The row's control.
    control: Control,
}

impl Row {
    /// Whether the row's Migrate box is checked.
    const fn included(&self) -> bool {
        matches!(self.control, Control::Include(true))
    }

    /// Whether the row has a Migrate box.
    const fn includes(&self) -> bool {
        matches!(self.control, Control::Include(_))
    }

    /// Whether the row has the choice of value.
    const fn resolves(&self) -> bool {
        matches!(self.control, Control::Resolve(_))
    }

    /// Whether the value `side` (`source` or `router`) is chosen.
    fn chose(&self, side: &str) -> bool {
        match self.control {
            Control::Resolve(Resolution::Source) => side == "source",
            Control::Resolve(Resolution::Router) => side == "router",
            Control::Resolve(Resolution::Undecided) | Control::None | Control::Include(_) => false,
        }
    }
}

impl Panel {
    /// The review of `visit`, filtered and paged by `view`.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(super) async fn new(visit: &Visit<'_>, view: &View) -> Self {
        let locale = visit.services().user().locale();
        let id = visit.record().id().to_owned();
        let shown = view.show.as_deref().and_then(Fate::from_slug);
        let mut panel = Self {
            shell: fragment_shell(locale),
            filters: Vec::new(),
            rows: Vec::new(),
            pager: Pager::paginate(Vec::<()>::new(), 1, String::new(), Vec::new()).1,
            error: String::new(),
            problem: String::new(),
            id,
        };
        let found =
            match visit.analysis().await {
                Ok(analysis) => visit.passwords().await.ok().and_then(|passwords| {
                    Classified::new(&analysis, visit.record(), &passwords).ok()
                }),
                Err(problem) => {
                    panel.problem = problem_text(&problem, locale);
                    return panel;
                }
            };
        let Some(classified) = found else {
            panel.problem = tr(locale, keys::WEB_MIGRATE_PROBLEM_SOURCE, None);
            return panel;
        };
        let record = visit.record();
        let all = classified
            .items()
            .iter()
            .map(|item| {
                let index = item.source_index;
                let excluded = record.excluded().contains(&index);
                let conflict = classified.conflicts(index);
                let resolution = conflict.then(|| {
                    if record.overwrite().contains(&index) {
                        Resolution::Source
                    } else if excluded {
                        Resolution::Router
                    } else {
                        Resolution::Undecided
                    }
                });
                let fate = Fate::of(item, conflict, excluded && !conflict);
                let control = match (resolution, fate) {
                    (Some(chosen), _) => Control::Resolve(chosen),
                    (None, Fate::Migrated | Fate::Input) => Control::Include(true),
                    (None, Fate::Excluded) => Control::Include(false),
                    (None, Fate::Conflict | Fate::Skipped | Fate::Unsupported) => Control::None,
                };
                Row {
                    index,
                    line: item.line_no,
                    fate: fate.slug(),
                    label: tr(locale, fate.label(), None),
                    reason: reason(item, resolution, locale),
                    before: item.before.clone(),
                    after: item
                        .after
                        .clone()
                        .filter(|after| *after != item.before)
                        .unwrap_or_default(),
                    control,
                }
            })
            .collect::<Vec<_>>();
        let fates = all.iter().map(|row| row.fate).collect::<Vec<_>>();
        let links = Fate::ALL.map(|fate| (fate.slug(), fate.label(), shown == Some(fate)));
        panel.filters = filters(&fates, links, (&screen::href::<Record>(&panel.id), locale));
        let picked = all
            .into_iter()
            .filter(|row| shown.is_none_or(|fate| row.fate == fate.slug()))
            .collect::<Vec<_>>();
        let query = shown.map_or_else(Vec::new, |fate| {
            vec![("show".to_owned(), fate.slug().to_owned())]
        });
        let (rows, pager) = Pager::paginate(
            picked,
            view.page.unwrap_or(1),
            format!("/ui/migrate/{}", panel.id),
            query,
        );
        panel.rows = rows;
        panel.pager = pager;
        panel
    }

    /// The panel refusing Continue with `error`.
    pub(super) fn refusing(mut self, error: String) -> Self {
        self.error = error;
        self
    }
}
