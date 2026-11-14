//! Schedules at `/ui/r/{router}/system/schedules`: the router's named schedules in a
//! filterable table, with Add schedule and Add action where the role may change them.
//!
//! Both are writes through the change workflow. The router's CLI takes the description
//! as one word, so the page checks for one before anything is sent.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{RouterCtx, schedules};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    shared::Visit,
    tables,
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::Controls, request::rendered},
    table::{
        Direction, Sort,
        rows::{Row, SortKey, Table, TableQuery},
        view::TableView,
    },
};

/// The page.
#[derive(Template)]
#[template(path = "pages/system_schedules.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why the schedules could not be read.
    problem: Option<MessageKey>,
    /// Whether the role may add schedules.
    add: bool,
    /// The schedules.
    region: Option<Region>,
}

localized!(Page);

/// The schedules table; a change sends it again out of band.
#[derive(Template)]
#[template(path = "partials/system_schedules_region.html")]
struct Region {
    /// Locale carrier.
    shell: Shell,
    /// The schedules shown.
    table: TableView,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Region);

/// One schedule as the table shows it.
#[derive(Debug, Clone)]
pub(crate) struct Schedule {
    /// Schedule name.
    name: String,
    /// Description.
    description: Option<String>,
    /// Whether it is active now.
    active: Option<bool>,
}

impl Row for Schedule {
    const COLUMNS: &'static [&'static str] = &["name", "description", "state"];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "description" => self
                .description
                .as_deref()
                .map_or(SortKey::Missing, SortKey::text),
            "state" => self.active.map_or(SortKey::Missing, |active| {
                SortKey::Number(i128::from(!active))
            }),
            _ => SortKey::text(&self.name),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.name.to_lowercase().contains(needle)
            || self
                .description
                .as_deref()
                .is_some_and(|text| text.to_lowercase().contains(needle))
    }
}

impl Schedule {
    /// Schedule name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Description.
    pub(super) fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Whether it is active now, when the router said.
    pub(super) const fn active(&self) -> Option<bool> {
        self.active
    }
}

/// The schedules of the router of `domain`.
///
/// # Errors
///
/// Returns the message to show when the router did not answer with its schedules.
// cancel-safe: reads only.
pub(crate) async fn read(domain: &RouterCtx) -> Result<Vec<Schedule>, MessageKey> {
    let states = schedules::read_schedules(domain).await.map_err(|error| {
        tracing::warn!(%error, "router schedules could not be read");
        keys::WEB_SYSTEM_READ_FAILED
    })?;
    Ok(states
        .into_iter()
        .filter_map(|state| {
            Some(Schedule {
                name: state.name?,
                description: state.description.filter(|text| !text.is_empty()),
                active: state.active,
            })
        })
        .collect())
}

/// Who looks at the schedules of which router, and the table query of the page.
pub(crate) struct Viewer<'call> {
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
    /// Filter, sort and page of the table.
    query: TableQuery,
}

impl<'call> Viewer<'call> {
    /// `user` looking at the schedules of `router` as `query` asks.
    pub(crate) const fn new(
        user: &'call CurrentUser,
        router: &'call str,
        query: TableQuery,
    ) -> Self {
        Self {
            user,
            router,
            query,
        }
    }

    /// What the role may do with the schedules of the router of `domain`.
    fn controls(&self, domain: &RouterCtx) -> Controls {
        Controls::new(self.user.role(), self.router)
            .with_operations(schedules::DESCRIPTOR.write_ops, Some(&domain.catalog))
    }

    /// The region for `rows`.
    fn region(&self, rows: Vec<Schedule>, controls: &Controls) -> Region {
        let table = Table::new(
            rows,
            &self.query,
            format!("/ui/r/{}/system/schedules", self.router),
        );
        let act = controls.allows("action");
        Region {
            shell: fragment_shell(self.user.locale()),
            table: tables::schedules(&table, act, (self.router, self.user.locale())),
            oob: false,
        }
    }

    /// The region read again through `domain` after a change, out of band.
    // cancel-safe: reads only.
    pub(crate) async fn refreshed(&self, domain: &RouterCtx) -> Option<String> {
        let rows = read(domain).await.ok()?;
        let controls = self.controls(domain);
        rendered(&Region {
            oob: true,
            ..self.region(rows, &controls)
        })
    }
}

/// `GET /ui/r/{router}/system/schedules`: the schedules and the controls the role may use.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(query): Form<TableQuery>,
) -> Response {
    let (shell, reading) = match Visit::new(&headers, &current, &user)
        .open(&state, &router)
        .await
    {
        Ok(opened) => opened,
        Err(refusal) => return refusal.into_response(),
    };
    let mut page = Page {
        shell,
        tabs: TabBar::new(router.clone(), Tab::Schedules),
        router: router.clone(),
        problem: None,
        add: false,
        region: None,
    };
    let viewer = Viewer::new(&user, &router, query);
    match reading {
        Ok((_, domain)) => {
            let controls = viewer.controls(&domain);
            page.add = controls.allows("create");
            match read(&domain).await {
                Ok(rows) => page.region = Some(viewer.region(rows, &controls)),
                Err(message) => page.problem = Some(message),
            }
        }
        Err(message) => page.problem = Some(message),
    }
    errors::render(&page)
}
