//! The command explorer page and its live fragments: search results, the group tree and
//! the command detail with its generated form.

use alloc::collections::BTreeMap;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::Deserialize;

use super::{
    detail::{self, CommandLink, Detail, Scope},
    lookup::{catalog_note, clip, facts_for, notice, problem},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        context::{self, Caller, fragment_shell},
        facts::RouterFacts,
        gate::Controls,
    },
};

/// Search results shown at most.
const SEARCH_LIMIT: usize = 50;

/// Commands per page of a group.
const GROUP_PAGE: usize = 50;

/// Query of the explorer page.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct PageQuery {
    /// Search text.
    #[serde(default, rename = "q")]
    search: String,
    /// Command to show.
    #[serde(default)]
    path: String,
}

impl PageQuery {
    /// Command to show.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }
}

/// Query of a group fragment.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct GroupQuery {
    /// Top-level command word.
    #[serde(default)]
    prefix: String,
    /// Page number, from 1.
    #[serde(default)]
    page: Option<usize>,
}

/// The explorer page.
#[derive(Template)]
#[template(path = "pages/explorer.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// Localized catalog line, such as "Command catalog 5.1 for KN-1811".
    catalog_note: String,
    /// Why no catalog is available.
    problem: Option<MessageKey>,
    /// The search text.
    query: String,
    /// Search results, when searching.
    results: Option<Results>,
    /// Top-level groups.
    groups: Vec<GroupEntry>,
    /// The selected command.
    detail: Option<Detail>,
    /// Whether the user may open the consoles.
    consoles: bool,
}

/// Search results.
struct Results {
    /// Matching commands, best first.
    items: Vec<CommandLink>,
    /// Localized count.
    summary: String,
    /// Whether more commands matched than shown.
    more: bool,
}

/// One top-level group of the tree.
struct GroupEntry {
    /// The command word.
    word: String,
    /// The word as a URL query value.
    query: String,
    /// Commands in the group.
    count: usize,
}

/// The search results fragment.
#[derive(Template)]
#[template(path = "partials/explorer_results.html")]
struct ResultsView {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The results.
    results: Results,
}

/// One page of a group.
#[derive(Template)]
#[template(path = "partials/explorer_group.html")]
struct GroupView {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The group word as a URL query value.
    prefix: String,
    /// Commands on this page.
    items: Vec<CommandLink>,
    /// Localized page position, empty for a single page.
    position: String,
    /// Previous page number.
    previous: Option<usize>,
    /// Next page number.
    next: Option<usize>,
}

/// The command detail fragment.
#[derive(Template)]
#[template(path = "partials/explorer_command.html")]
struct CommandView {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The command.
    detail: Detail,
}

localized!(Page);

localized!(ResultsView);

localized!(GroupView);

localized!(CommandView);

/// `GET /ui/r/{router}/explorer`: search, groups and, with `?path=`, one command.
// NOT cancel-safe: it only reads router state to render the page, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(query): Form<PageQuery>,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Advanced, Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let controls = Controls::new(user.role(), &router);
    let mut page = Page {
        shell,
        consoles: controls.holds(Permission::RawRci),
        router: router.clone(),
        catalog_note: String::new(),
        problem: None,
        query: clip(&query.search).to_owned(),
        results: None,
        groups: Vec::new(),
        detail: None,
    };
    let facts = match target.facts(&state).await {
        Ok(found) => found,
        Err(error) => {
            page.problem = Some(problem(error));
            return errors::render(&page);
        }
    };
    let locale = user.locale();
    page.catalog_note = catalog_note(&facts, locale);
    page.groups = groups(&facts);
    if !page.query.is_empty() {
        page.results = Some(results(&facts, &page.query, locale));
    }
    let scope = Scope::new(&facts, controls, locale).with_jobs(state.advanced().jobs().is_some());
    page.detail = detail::detail(&scope, clip(&query.path));
    errors::render(&page)
}

/// `GET /ui/r/{router}/explorer/search?q=`: the live search results.
// NOT cancel-safe: it only detects the router and searches its catalog, but it may sign in first,
// and a sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn search(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(query): Form<PageQuery>,
) -> Response {
    let (_, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let text = clip(&query.search);
    if text.is_empty() {
        return notice(user.locale(), "neutral", keys::WEB_EXPLORER_SEARCH_EMPTY);
    }
    errors::render(&ResultsView {
        shell: fragment_shell(user.locale()),
        router,
        results: results(&facts, text, user.locale()),
    })
}

/// `GET /ui/r/{router}/explorer/group?prefix=&page=`: one page of a group's commands.
// NOT cancel-safe: it only detects the router and reads its catalog, but it may sign in first, and
// a sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn group(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(query): Form<GroupQuery>,
) -> Response {
    let (_, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let commands = detail::group_commands(facts.catalog(), clip(&query.prefix));
    let pages = commands.len().div_ceil(GROUP_PAGE).max(1);
    let current = query.page.unwrap_or(1).clamp(1, pages);
    let first = current.saturating_sub(1).saturating_mul(GROUP_PAGE);
    let position = if pages > 1 {
        let mut args = FluentArgs::new();
        args.set("page", current.to_string());
        args.set("pages", pages.to_string());
        tr(user.locale(), keys::WEB_EXPLORER_PAGE_OF, Some(&args))
    } else {
        String::new()
    };
    errors::render(&GroupView {
        shell: fragment_shell(user.locale()),
        router,
        prefix: detail::encode(clip(&query.prefix)),
        items: detail::links(commands.into_iter().skip(first).take(GROUP_PAGE)),
        position,
        previous: (current > 1).then(|| current.saturating_sub(1)),
        next: (current < pages).then(|| current.saturating_add(1)),
    })
}

/// `GET /ui/r/{router}/explorer/command?path=`: the detail and form of one command.
// NOT cancel-safe: it only detects the router and reads its catalog, but it may sign in first, and
// a sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn command(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(query): Form<PageQuery>,
) -> Response {
    let (_, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let scope = Scope::new(&facts, Controls::new(user.role(), &router), user.locale())
        .with_jobs(state.advanced().jobs().is_some());
    detail::detail(&scope, clip(&query.path)).map_or_else(
        || notice(user.locale(), "error", keys::WEB_EXPLORER_UNKNOWN_COMMAND),
        |found| {
            errors::render(&CommandView {
                shell: fragment_shell(user.locale()),
                router: router.clone(),
                detail: found,
            })
        },
    )
}

/// The search results of `text`.
fn results(facts: &RouterFacts, text: &str, locale: Locale) -> Results {
    let found = facts.catalog().search(text, SEARCH_LIMIT.saturating_add(1));
    let more = found.len() > SEARCH_LIMIT;
    let items = detail::links(found.iter().take(SEARCH_LIMIT).map(|result| result.command));
    let mut args = FluentArgs::new();
    args.set("count", items.len());
    Results {
        summary: tr(locale, keys::WEB_EXPLORER_RESULTS, Some(&args)),
        items,
        more,
    }
}

/// The top-level groups of the catalog with their sizes.
fn groups(facts: &RouterFacts) -> Vec<GroupEntry> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for command in facts.catalog().commands() {
        let word = command.path.split_whitespace().next().unwrap_or_default();
        let count = counts.entry(word).or_default();
        *count = count.saturating_add(1);
    }
    counts
        .into_iter()
        .map(|(word, count)| GroupEntry {
            word: word.to_owned(),
            query: detail::encode(word),
            count,
        })
        .collect()
}
