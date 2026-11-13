//! The router's services at `/ui/r/{router}/system/services`: every service the router's
//! catalog knows, whether the router's configuration turns it on, and Turn on or Turn off
//! where the role may change it.
//!
//! HTTP, SSH and Telnet carry management access: switching them is a management change.
//! It needs `Destructive` besides `Write`, asks first with the kit's dialog explaining the
//! fail-safe timer, and runs inside that timer.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_app::permissions::Permission;
use kcc_catalog::{Catalog, Risk};
use kcc_domain::{RouterCtx, configuration::SafetyNet, services};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    shared::{Visit, rendered, with_query},
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page::{Localize, Shell},
    page_kit::{context::fragment_shell, gate::Controls},
    table::{
        Direction, Sort,
        rows::{Row, SortKey, Table, TableQuery},
    },
};

/// The page.
#[derive(Template)]
#[template(path = "pages/system_services.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why the services could not be read.
    problem: Option<MessageKey>,
    /// The services.
    region: Option<Region>,
}

impl Localize for Page {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// The services table; a change sends it again out of band.
#[derive(Template)]
#[template(path = "partials/system_services_region.html")]
struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The services shown.
    table: Table<Service>,
    /// Whether the role may switch ordinary services.
    plain: bool,
    /// Whether the role may switch management services.
    management: bool,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

impl Localize for Region {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Region {
    /// Whether the role may switch `service`.
    const fn switchable(&self, service: &Service) -> bool {
        if service.management {
            self.management
        } else {
            self.plain
        }
    }

    /// The endpoint switching `service` to the other state.
    fn toggle_url(&self, service: &Service) -> String {
        let wanted = if service.on { "false" } else { "true" };
        with_query(
            &format!("/ui/r/{}/system/services/toggle", self.router),
            &[("name", &service.name), ("on", wanted)],
        )
    }
}

/// One service as the table shows it.
#[derive(Debug, Clone)]
struct Service {
    /// Catalog service name, such as `ssh`.
    name: String,
    /// Whether the configuration turns it on.
    on: bool,
    /// Whether it carries management access.
    management: bool,
}

impl Row for Service {
    const COLUMNS: &'static [&'static str] = &["name", "state"];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "state" => SortKey::Number(i128::from(!self.on)),
            _ => SortKey::text(&self.name),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.name.contains(needle)
    }
}

impl Service {
    /// Catalog service name.
    fn name(&self) -> &str {
        &self.name
    }

    /// Whether the configuration turns it on.
    const fn on(&self) -> bool {
        self.on
    }

    /// Whether it carries management access.
    const fn management(&self) -> bool {
        self.management
    }
}

/// The service names the router's catalog knows, one word each.
pub(crate) fn known(catalog: &Catalog) -> Vec<String> {
    catalog
        .commands()
        .filter_map(|command| command.path.strip_prefix("service "))
        .filter(|name| !name.contains(' '))
        .map(str::to_owned)
        .collect()
}

/// The services of the router of `domain`, on as its configuration says.
///
/// # Errors
///
/// Returns the message to show when the router did not answer with its services.
// cancel-safe: reads only.
async fn read(domain: &RouterCtx) -> Result<Vec<Service>, MessageKey> {
    let configured = services::read_services(domain).await.map_err(|error| {
        tracing::warn!(%error, "router services could not be read");
        keys::WEB_SYSTEM_READ_FAILED
    })?;
    Ok(known(&domain.catalog)
        .into_iter()
        .map(|name| Service {
            on: configured.iter().any(|service| {
                service.name.as_deref() == Some(name.as_str()) && service.enabled != Some(false)
            }),
            management: services::service_risk(&name) == Risk::Management,
            name,
        })
        .collect())
}

/// Who looks at the services of which router, and the table query of the page.
pub(crate) struct Viewer<'call> {
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
    /// Filter, sort and page of the table.
    query: TableQuery,
}

impl<'call> Viewer<'call> {
    /// `user` looking at the services of `router` as `query` asks.
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

    /// The services region for `rows`.
    fn region(&self, rows: Vec<Service>) -> Region {
        let controls = Controls::new(self.user.role(), self.router);
        Region {
            shell: fragment_shell(self.user.locale()),
            router: self.router.to_owned(),
            table: Table::new(
                rows,
                &self.query,
                format!("/ui/r/{}/system/services", self.router),
            ),
            plain: controls.permits(&SafetyNet::required(Permission::Write, Risk::Write)),
            management: controls.permits(&SafetyNet::required(Permission::Write, Risk::Management)),
            oob: false,
        }
    }

    /// The services region read again through `domain` after a change, out of band.
    // cancel-safe: reads only.
    pub(crate) async fn refreshed(&self, domain: &RouterCtx) -> Option<String> {
        let rows = read(domain).await.ok()?;
        rendered(&Region {
            oob: true,
            ..self.region(rows)
        })
    }
}

/// `GET /ui/r/{router}/system/services`: the services and the switches the role may use.
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
    let viewer = Viewer::new(&user, &router, query);
    let (region, problem) = match reading {
        Ok((_, domain)) => match read(&domain).await {
            Ok(rows) => (Some(viewer.region(rows)), None),
            Err(message) => (None, Some(message)),
        },
        Err(message) => (None, Some(message)),
    };
    errors::render(&Page {
        shell,
        tabs: TabBar::new(router.clone(), Tab::Services),
        router,
        problem,
        region,
    })
}
