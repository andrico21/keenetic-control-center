//! The internet connections page at `/ui/r/{router}/internet`.
//!
//! The internet state the router reports, every IPoE, PPPoE, L2TP and PPTP connection in a
//! filterable table ordered by priority, where Move up and Move down swap two
//! neighbours' priorities, and the router's ping-check profiles, read-only. Adding a
//! connection, a connection's settings and Delete are in `net_internet_edit` and
//! `net_internet_create`.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::{DomainError, RouterCtx, internet, wan};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};
use serde_json::Value;

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    net_change::scalar,
    net_internet_order::reorder,
    net_pages::{Call, Tab, Tabs, Viewer},
    net_wan::{Link, links},
    page::{Localize as _, Shell},
    page_kit::{
        context,
        context::{Caller, fragment_shell},
        family::Family,
        gate::Controls,
        request::{rendered, with_query},
    },
    table::rows::{Row as _, Table, TableQuery},
};

/// The page.
#[derive(Template)]
#[template(path = "pages/net_internet.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The network pages' tab bar.
    tabs: Tabs,
    /// The connections, when the router answered.
    listing: Option<Listing>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
    /// Whether the role may add a connection.
    can_create: bool,
}

localized!(Page);

/// `GET /ui/r/{router}/internet`: the internet state, the connections and the ping-check
/// profiles.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Tab::Internet.section(), Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let mut page = Page {
        shell,
        tabs: Tabs::new(&router, Tab::Internet),
        router: router.clone(),
        listing: None,
        problem: None,
        can_create: false,
    };
    match target.context(&state).await {
        Ok((facts, domain)) => {
            let controls = Controls::new(user.role(), &router)
                .with_operations(wan::DESCRIPTOR.write_ops, Some(facts.catalog()));
            page.can_create = controls.allows("create");
            let viewer = Call::new(&state, &user, &router, &headers).viewer(controls);
            match Listing::read(&domain, viewer, &query).await {
                Ok(listing) => page.listing = Some(listing),
                Err(error) => {
                    tracing::warn!(%error, "internet page: router read failed");
                    page.problem = Some(Family::Changes.unreachable());
                }
            }
        }
        Err(error) => page.problem = Some(error.message(Family::Changes)),
    }
    errors::render(&page)
}

/// The connections read back after a change, out of band, keeping the page's filter,
/// order and page.
// cancel-safe: reads only.
pub(crate) async fn refreshed(call: Call<'_>, domain: &RouterCtx) -> Option<String> {
    let controls = Controls::new(call.user().role(), call.router())
        .with_operations(wan::DESCRIPTOR.write_ops, Some(&domain.catalog));
    let listing = Listing::read(domain, call.viewer(controls), &call.shown_query())
        .await
        .inspect_err(|error| tracing::warn!(%error, "connections read-back failed"))
        .ok()?;
    rendered(&listing.out_of_band())
}

/// The internet state, the connections and the ping-check profiles; a change sends them
/// again out of band.
#[derive(Template)]
#[template(path = "partials/net_internet_region.html")]
struct Listing {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// Whether the router reaches the internet, when reported.
    online: Option<bool>,
    /// The page of connections shown.
    table: Table<Link>,
    /// The ping-check profiles.
    profiles: Vec<Profile>,
    /// What the role may change.
    controls: Controls,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Listing);

impl Listing {
    /// Reads the router of `domain` and cuts the page `query` asks for.
    ///
    /// # Errors
    ///
    /// Returns the router's error for the connections; the internet state and the
    /// ping-check profiles are left unreported when unreadable.
    // cancel-safe: reads only.
    async fn read(
        domain: &RouterCtx,
        viewer: Viewer,
        query: &TableQuery,
    ) -> Result<Self, DomainError> {
        let found = links(domain).await?;
        let online = internet::read_status(domain)
            .await
            .ok()
            .and_then(|status| status.extra.get("internet").and_then(Value::as_bool));
        let profiles = internet::read_ping_check(domain)
            .await
            .ok()
            .and_then(|checks| checks.profile)
            .map(|value| profiles(&value))
            .unwrap_or_default();
        let (router, locale, controls) = viewer.into_parts();
        Ok(Self {
            shell: fragment_shell(locale),
            table: Table::new(found, query, format!("/ui/r/{router}/internet")),
            router,
            online,
            profiles,
            controls,
            oob: false,
        })
    }

    /// The region as an out-of-band replacement of the page's.
    const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The internet state in the reader's language.
    fn online_text(&self) -> String {
        let key = match self.online {
            Some(true) => keys::WEB_INTERNET_CONNECTED,
            Some(false) => keys::WEB_INTERNET_DISCONNECTED,
            None => keys::WEB_INTERNET_UNKNOWN,
        };
        tr(self.shell.locale(), key, None)
    }

    /// "3 of 12" while a filter hides rows.
    fn count(&self) -> Option<String> {
        (!self.table.filter().is_empty()).then(|| {
            let mut args = FluentArgs::new();
            args.set("count", self.table.matched());
            args.set("total", self.table.total());
            tr(self.shell.locale(), keys::WEB_KIT_TABLE_COUNT, Some(&args))
        })
    }

    /// The settings dialog of `link`.
    fn settings_url(&self, link: &Link) -> String {
        with_query(
            &format!("/ui/r/{}/internet/settings", self.router),
            &[("name", link.id())],
        )
    }

    /// The Delete dialog of `link`, when the role may delete.
    fn delete_url(&self, link: &Link) -> Option<String> {
        self.controls.allows("delete").then(|| {
            with_query(
                &format!("/ui/r/{}/internet/delete", self.router),
                &[("name", link.id())],
            )
        })
    }

    /// Move up (or down) for `link`, when the table shows the priority order, the role may
    /// change priorities and a neighbour can swap with it.
    fn move_url(&self, link: &Link, up: bool) -> Option<String> {
        let ordered = self.table.sort() == Link::DEFAULT && self.table.filter().is_empty();
        (ordered
            && self.controls.allows("priority")
            && !reorder(self.table.rows(), link.id(), up).is_empty())
        .then(|| {
            with_query(
                &format!("/ui/r/{}/internet/order", self.router),
                &[
                    ("name", link.id()),
                    ("move", if up { "up" } else { "down" }),
                ],
            )
        })
    }
}

/// One ping-check profile, as reported.
#[derive(Debug, Clone)]
struct Profile {
    /// Profile name.
    name: String,
    /// Hosts checked, comma-separated.
    hosts: Option<String>,
    /// Check method.
    mode: Option<String>,
    /// Seconds between checks.
    interval: Option<String>,
}

/// The ping-check profiles of a `show ping-check` `profile` member: a list, or an object
/// keyed by profile name.
fn profiles(value: &Value) -> Vec<Profile> {
    let named: Vec<(String, &Value)> = match value {
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let name =
                    scalar(item.get("name")).unwrap_or_else(|| index.saturating_add(1).to_string());
                (name, item)
            })
            .collect(),
        Value::Object(map) => map
            .iter()
            .map(|(name, item)| (name.clone(), item))
            .collect(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Vec::new(),
    };
    named
        .into_iter()
        .map(|(name, item)| Profile {
            name,
            hosts: hosts(item.get("host")),
            mode: scalar(item.get("mode")),
            interval: scalar(item.get("update-interval")).or_else(|| scalar(item.get("interval"))),
        })
        .collect()
}

/// The hosts of a profile: one host, or a list of hosts.
fn hosts(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Array(items) => {
            let listed: Vec<String> = items.iter().filter_map(|item| scalar(Some(item))).collect();
            (!listed.is_empty()).then(|| listed.join(", "))
        }
        other @ (Value::Null
        | Value::Bool(_)
        | Value::Number(_)
        | Value::String(_)
        | Value::Object(_)) => scalar(Some(other)),
    }
}
