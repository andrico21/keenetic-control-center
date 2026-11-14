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
use kcc_domain::{DomainError, RouterCtx, internet, wan};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::Value;

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    net_change::scalar,
    net_pages::{Call, Tab, Tabs, Viewer},
    net_tables::connections_view,
    net_wan::links,
    page::{Localize as _, Shell},
    page_kit::{
        context,
        context::{Caller, fragment_shell},
        family::Family,
        gate::Controls,
        request::rendered,
    },
    table::{
        cells::Cell,
        head::Head,
        rows::{Table, TableQuery},
        view::TableView,
    },
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
    /// Whether the router reaches the internet, when reported.
    online: Option<bool>,
    /// The page of connections shown.
    table: TableView,
    /// The ping-check profiles.
    ping: TableView,
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
            .map_or_default(|value| profiles(&value));
        let (router, locale, controls) = viewer.into_parts();
        let table = Table::new(found, query, format!("/ui/r/{router}/internet"));
        Ok(Self {
            shell: fragment_shell(locale),
            table: connections_view(&router, &table, (&controls, locale)),
            online,
            ping: ping_view(&profiles, locale),
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

    /// The ping-check profiles table.
    const fn ping_table(&self) -> &TableView {
        &self.ping
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

/// The ping-check profiles: name, hosts, mode and interval of each.
fn ping_view(profiles: &[Profile], locale: Locale) -> TableView {
    let mut view = TableView::new("table").nested();
    if profiles.is_empty() {
        return view.blank(
            "panel__note",
            tr(locale, keys::WEB_INTERNET_PING_NONE, None),
        );
    }
    for key in [
        keys::WEB_INTERNET_PING_PROFILE,
        keys::WEB_INTERNET_PING_HOSTS,
        keys::WEB_INTERNET_PING_MODE,
        keys::WEB_INTERNET_PING_INTERVAL,
    ] {
        view = view.head(Head::plain(tr(locale, key, None)));
    }
    for profile in profiles {
        view = view.row(vec![
            Cell::code(profile.name.clone()).head(),
            Cell::reported(locale, profile.hosts.clone()).class("mono"),
            Cell::reported(locale, profile.mode.clone()),
            Cell::reported(locale, profile.interval.clone()).class("numeric"),
        ]);
    }
    view
}
