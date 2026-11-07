//! Step 4: every setting of the plan and what happens to it on the router.
//!
//! Filtered by fate and paged by 50; Apply leaves a setting in or out, and choices save
//! as they change (`review_submit`).

use core::iter;

use askama::Template;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;

use super::{
    access::Visit,
    fates::{Fate, reason},
    lines::{redacted, shown},
    plan::{Basis, plan_problem},
    screen,
    target::problem_text,
};
use crate::{
    page::{Localize, Shell},
    page_kit::context::fragment_shell,
    table::pager::Pager,
};

/// The review's filter and page.
#[derive(Debug, Default, Deserialize)]
pub(super) struct View {
    /// The fate shown; all when absent.
    #[serde(default)]
    show: Option<String>,
    /// The page shown, from 1.
    #[serde(default)]
    page: Option<usize>,
}

/// The step's panel.
#[derive(Template)]
#[template(path = "partials/presets_review.html")]
pub(super) struct Panel {
    /// Locale carrier.
    shell: Shell,
    /// Run id.
    id: String,
    /// The filter links: link, label, whether shown.
    filters: Vec<(String, String, bool)>,
    /// The shown page of settings.
    rows: Vec<Row>,
    /// The page links.
    pager: Pager,
    /// Why the settings cannot be shown.
    problem: String,
}

impl Localize for Panel {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// One setting.
struct Row {
    /// Its plan index, the form's value.
    index: usize,
    /// Its fate's filter name.
    fate: &'static str,
    /// Its pill's tone.
    tone: &'static str,
    /// Its fate.
    label: String,
    /// Why.
    reason: String,
    /// The setting, redacted.
    before: String,
    /// What the router gets, redacted, when it differs.
    after: String,
    /// Whether it has an Apply box, and whether that is checked.
    include: Option<bool>,
}

impl Panel {
    /// The review of `visit`, filtered and paged by `view`.
    // cancel-safe: reads only.
    pub(super) async fn new(visit: &Visit<'_>, view: &View) -> Self {
        let locale = visit.services().user().locale();
        let id = visit.record().id().to_owned();
        let shown_fate = view
            .show
            .as_deref()
            .and_then(|slug| Fate::ALL.into_iter().find(|fate| fate.slug() == slug));
        let mut panel = Self {
            shell: fragment_shell(locale),
            filters: Vec::new(),
            rows: Vec::new(),
            pager: Pager::paginate(Vec::<()>::new(), 1, String::new(), Vec::new()).1,
            problem: String::new(),
            id,
        };
        let all = match rows(visit, locale).await {
            Ok(found) => found,
            Err(problem) => {
                panel.problem = problem;
                return panel;
            }
        };
        panel.filters = filters(&all, shown_fate, &panel.id, locale);
        let picked = all
            .into_iter()
            .filter(|row| shown_fate.is_none_or(|fate| row.fate == fate.slug()))
            .collect::<Vec<_>>();
        let query = shown_fate.map_or_else(Vec::new, |fate| {
            vec![("show".to_owned(), fate.slug().to_owned())]
        });
        let (rows, pager) = Pager::paginate(
            picked,
            view.page.unwrap_or(1),
            screen::href(&panel.id),
            query,
        );
        panel.rows = rows;
        panel.pager = pager;
        panel
    }
}

/// Every setting of `visit`'s plan, or why there is none.
///
/// # Errors
///
/// Returns the sentence explaining why the plan cannot be made.
// cancel-safe: reads only.
async fn rows(visit: &Visit<'_>, locale: Locale) -> Result<Vec<Row>, String> {
    let basis = Basis::of(visit)
        .await
        .map_err(|problem| problem_text(&problem, locale))?;
    let record = visit.record();
    let plan = basis
        .plan(record)
        .map_err(|error| problem_text(&plan_problem(&error), locale))?;
    let lines = &basis.preset().lines;
    Ok(plan
        .items
        .iter()
        .map(|item| {
            let fate = Fate::of(item, record.excluded().contains(&item.index));
            let before = lines.get(item.index).map_or_else(
                || item.expose_command().map(redacted).unwrap_or_default(),
                shown,
            );
            let after = item
                .expose_result()
                .map(redacted)
                .filter(|result| *result != before)
                .unwrap_or_default();
            Row {
                index: item.index,
                fate: fate.slug(),
                tone: fate.tone(),
                label: tr(locale, fate.label(), None),
                reason: reason(item, fate, record, locale),
                before,
                after,
                include: fate.choosable().then_some(fate != Fate::Excluded),
            }
        })
        .collect())
}

/// The filter links over `rows`, `shown` marked.
fn filters(
    rows: &[Row],
    shown: Option<Fate>,
    id: &str,
    locale: Locale,
) -> Vec<(String, String, bool)> {
    let base = screen::href(id);
    let all = (
        base.clone(),
        format!(
            "{} ({})",
            tr(locale, keys::WEB_MIGRATE_FATE_ALL, None),
            rows.len()
        ),
        shown.is_none(),
    );
    let each = Fate::ALL.into_iter().filter_map(|fate| {
        let count = rows.iter().filter(|row| row.fate == fate.slug()).count();
        (count > 0).then(|| {
            (
                format!("{base}?show={}", fate.slug()),
                format!("{} ({count})", tr(locale, fate.label(), None)),
                shown == Some(fate),
            )
        })
    });
    iter::once(all).chain(each).collect()
}
