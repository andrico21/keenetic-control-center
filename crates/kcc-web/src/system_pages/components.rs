//! Firmware components at `/ui/r/{router}/system/components`.
//!
//! The firmware, the components with the changes queued for them, Check for updates,
//! Install and Remove, and the commit that applies the queue (`component_commit`).
//!
//! Queueing and checking are writes; nothing reaches the firmware until the commit, a
//! destructive change that restarts the router.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{
    RouterCtx,
    components::{self, QueueAction},
    system,
};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    shared::{Visit, rendered, with_query},
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::Controls},
    table::{
        Direction, Sort,
        rows::{Row, SortKey, Table, TableQuery},
    },
};

/// The page.
#[derive(Template)]
#[template(path = "pages/system_components.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why the components could not be read.
    problem: Option<MessageKey>,
    /// The firmware title, when the router reported it.
    firmware: Option<String>,
    /// Whether the role may check for updates.
    check: bool,
    /// The components.
    region: Option<Region>,
}

localized!(Page);

/// The queue and the components table; a change sends it again out of band.
#[derive(Template)]
#[template(path = "partials/system_components_region.html")]
pub(crate) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The components shown.
    table: Table<Component>,
    /// The queued changes, in name order.
    queued: Vec<Component>,
    /// Whether the role may queue changes.
    queue: bool,
    /// Whether the role may commit the queue.
    commit: bool,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Region);

/// Where a component stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Installed.
    Installed,
    /// Not installed.
    Available,
    /// Queued for installation.
    Installing,
    /// Queued for removal.
    Removing,
}

/// One component as the table shows it.
#[derive(Debug, Clone)]
pub(crate) struct Component {
    /// Component name.
    name: String,
    /// Where it stands.
    stage: Stage,
}

impl Row for Component {
    const COLUMNS: &'static [&'static str] = &["name", "state"];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "state" => SortKey::text(self.stage.slug()),
            _ => SortKey::text(&self.name),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.name.to_lowercase().contains(needle)
    }
}

impl Stage {
    /// A stable word for sorting.
    const fn slug(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Available => "available",
            Self::Installing => "installing",
            Self::Removing => "removing",
        }
    }

    /// The state as the table says it.
    const fn label(self) -> MessageKey {
        match self {
            Self::Installed => keys::WEB_SYSTEM_COMPONENTS_INSTALLED,
            Self::Available => keys::WEB_SYSTEM_COMPONENTS_AVAILABLE,
            Self::Installing => keys::WEB_SYSTEM_COMPONENTS_INSTALLING,
            Self::Removing => keys::WEB_SYSTEM_COMPONENTS_REMOVING,
        }
    }
}

impl Component {
    /// Component name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The state's label.
    const fn label(&self) -> MessageKey {
        self.stage.label()
    }

    /// Whether a change is queued for it.
    const fn queued(&self) -> bool {
        matches!(self.stage, Stage::Installing | Stage::Removing)
    }

    /// The queue action the row offers: install what is available, remove what is
    /// installed.
    pub(crate) const fn action(&self) -> Option<QueueAction> {
        match self.stage {
            Stage::Available => Some(QueueAction::Install),
            Stage::Installed => Some(QueueAction::Remove),
            Stage::Installing | Stage::Removing => None,
        }
    }
}

impl Region {
    /// The row's queue button: its endpoint and label.
    fn queue_button(&self, component: &Component) -> Option<(String, MessageKey)> {
        let (word, label) = match component.action()? {
            QueueAction::Install => ("install", keys::WEB_SYSTEM_COMPONENTS_INSTALL),
            QueueAction::Remove | _ => ("remove", keys::WEB_SYSTEM_COMPONENTS_REMOVE),
        };
        let href = with_query(
            &format!("/ui/r/{}/system/components/queue", self.router),
            &[("name", &component.name), ("action", word)],
        );
        Some((href, label))
    }
}

/// The components of the router of `domain`, with the changes queued for them.
///
/// # Errors
///
/// Returns the message to show when the router did not answer with its components.
// cancel-safe: reads only.
pub(crate) async fn read(domain: &RouterCtx) -> Result<Vec<Component>, MessageKey> {
    let read = (
        components::read_components(domain).await,
        components::read_pending(domain).await,
    );
    let (Ok(listed), Ok(pending)) = read else {
        tracing::warn!("router components could not be read");
        return Err(keys::WEB_SYSTEM_READ_FAILED);
    };
    Ok(listed
        .into_iter()
        .filter_map(|component| {
            let name = component.name?;
            let stage = if pending.install.contains(&name) {
                Stage::Installing
            } else if pending.remove.contains(&name) {
                Stage::Removing
            } else if component.installed == Some(true) {
                Stage::Installed
            } else {
                Stage::Available
            };
            Some(Component { name, stage })
        })
        .collect())
}

/// Who looks at the components of which router, and the table query of the page.
pub(crate) struct Viewer<'call> {
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
    /// Filter, sort and page of the table.
    query: TableQuery,
}

impl<'call> Viewer<'call> {
    /// `user` looking at the components of `router` as `query` asks.
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

    /// What the role may do with the components of the router of `domain`.
    pub(crate) fn controls(&self, domain: &RouterCtx) -> Controls {
        Controls::new(self.user.role(), self.router)
            .with_operations(components::DESCRIPTOR.write_ops, Some(&domain.catalog))
    }

    /// The region for `rows`.
    fn region(&self, rows: Vec<Component>, controls: &Controls) -> Region {
        let mut queued: Vec<Component> = rows
            .iter()
            .filter(|component| component.queued())
            .cloned()
            .collect();
        queued.sort_by(|left, right| left.name.cmp(&right.name));
        Region {
            shell: fragment_shell(self.user.locale()),
            router: self.router.to_owned(),
            table: Table::new(
                rows,
                &self.query,
                format!("/ui/r/{}/system/components", self.router),
            ),
            queued,
            queue: controls.allows("install") && controls.allows("remove"),
            commit: controls.allows("commit"),
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

/// `GET /ui/r/{router}/system/components`: the firmware, the queue and the components.
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
        tabs: TabBar::new(router.clone(), Tab::Components),
        router: router.clone(),
        problem: None,
        firmware: None,
        check: false,
        region: None,
    };
    let viewer = Viewer::new(&user, &router, query);
    match reading {
        Ok((_, domain)) => {
            let controls = viewer.controls(&domain);
            page.check = controls.allows("check_update");
            page.firmware = system::read_version(&domain)
                .await
                .ok()
                .and_then(|version| version.title.or(version.release))
                .filter(|title| !title.is_empty());
            match read(&domain).await {
                Ok(rows) => page.region = Some(viewer.region(rows, &controls)),
                Err(message) => page.problem = Some(message),
            }
        }
        Err(message) => page.problem = Some(message),
    }
    errors::render(&page)
}
