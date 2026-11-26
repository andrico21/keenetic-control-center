//! The fleet overview at `/ui/` and its live stream at `/ui/sse/fleet`.
//!
//! The page renders one card per router the role may read, waiting briefly for a first
//! poll; the stream then sends each card again, re-rendered in the viewer's locale, every
//! time the shared poller reports that router.

extern crate alloc;

use alloc::sync::Arc;
use core::{convert::Infallible, time::Duration};

use askama::Template;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse as _, Redirect, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::{
    Stream, StreamExt as _,
    future::join_all,
    stream::{self, BoxStream},
};
use kcc_app::{
    permissions::{Permission, Role},
    registry::RegistryEntry,
};
use kcc_i18n::keys;
use serde::Deserialize;

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{FleetEntry, Localize as _, Shell, Theme},
    prefs,
    stream_session::StreamSession,
    telemetry::Feed,
    view::RouterView,
};

/// How long a page waits for the first poll of a router it shows.
pub(crate) const FIRST_POLL_WAIT: Duration = Duration::from_secs(3);

/// The fleet switcher's query: `/ui/?router=<id>` opens that router's dashboard.
#[derive(Debug, Deserialize)]
pub(crate) struct FleetQuery {
    /// Router picked in the header switcher.
    router: Option<String>,
}

/// The fleet grid.
#[derive(Template)]
#[template(path = "pages/fleet.html")]
struct FleetPage {
    /// Page shell.
    shell: Shell,
    /// Whether fleet services are attached.
    available: bool,
    /// Whether the role may add routers.
    can_add: bool,
    /// One card per visible router.
    cards: Vec<RouterView>,
}

localized!(FleetPage);

/// One card's content, sent by the stream.
#[derive(Template)]
#[template(path = "partials/router_card.html")]
struct CardFragment {
    /// Locale carrier.
    shell: Shell,
    /// The card.
    card: RouterView,
}

localized!(CardFragment);

/// `GET /ui/`: the fleet grid, or the dashboard of the router picked in the switcher.
// cancel-safe: it only reads the router list and waits on the routers' telemetry feeds.
pub(crate) async fn page(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(query): Form<FleetQuery>,
) -> Response {
    if let Some(router) = query.router.filter(|id| is_profile_id(id)) {
        return Redirect::to(&format!("/ui/r/{router}")).into_response();
    }
    let shell = prefs::shell_for_locale(&headers, user.locale())
        .with_csrf_token(current.session().csrf_token().to_owned())
        .with_section(Section::Dashboard);
    let Some(fleet) = state.fleet() else {
        return errors::render(&FleetPage {
            shell,
            available: false,
            can_add: false,
            cards: Vec::new(),
        });
    };
    let entries = match fleet.visible(user.role()).await {
        Ok(entries) => entries,
        Err(error) => return errors::internal(&error, shell),
    };
    let feeds = feeds(&state, &entries).await;
    let states = join_all(feeds.iter().map(|feed| feed.first(FIRST_POLL_WAIT))).await;
    let cards = entries
        .iter()
        .zip(&states)
        .map(|(entry, live)| RouterView::new(entry, live, user.locale()).allow(user.role()))
        .collect();
    errors::render(&FleetPage {
        shell: shell.with_fleet(switcher(&entries, None), None),
        available: true,
        can_add: user.role().grants(Permission::ManageRouters),
        cards,
    })
}

/// `GET /ui/sse/fleet`: an event named `router-<id>` with the re-rendered card whenever
/// the poller reports a visible router.
// cancel-safe: it only reads the router list and subscribes to the routers' telemetry feeds.
pub(crate) async fn stream(
    State(state): State<WebState>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let Some(fleet) = state.fleet() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(slot) = StreamSession::open(&state, &current, &user) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let entries = match fleet.visible(user.role()).await {
        Ok(entries) => entries,
        Err(error) => {
            tracing::error!(%error, "fleet stream could not list routers");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let feeds = feeds(&state, &entries).await;
    let cards: Vec<BoxStream<'static, Event>> = entries
        .into_iter()
        .zip(feeds)
        .map(|(entry, feed)| card_events(entry, feed, &user))
        .collect();
    guarded(stream::select_all(cards), slot).into_response()
}

/// The feed of every entry, in entry order.
// cancel-safe: it only subscribes to telemetry feeds; an abandoned feed stops when dropped.
async fn feeds(state: &WebState, entries: &[RegistryEntry]) -> Vec<Arc<Feed>> {
    let Some(fleet) = state.fleet() else {
        return Vec::new();
    };
    let mut feeds = Vec::with_capacity(entries.len());
    for entry in entries {
        feeds.push(fleet.telemetry().feed(&entry.profile.id).await);
    }
    feeds
}

/// The card events of one router: its current card once polled, then one per update.
fn card_events(
    entry: RegistryEntry,
    feed: Arc<Feed>,
    user: &CurrentUser,
) -> BoxStream<'static, Event> {
    let locale = user.locale();
    let role = user.role().clone();
    let watcher = feed.subscribe();
    stream::unfold(
        (watcher, feed, true),
        move |(mut updates, holder, first)| {
            let card_entry = entry.clone();
            let card_role = role.clone();
            async move {
                if !(first && updates.borrow_and_update().polled()) {
                    updates.changed().await.ok()?;
                }
                let latest = updates.borrow_and_update().clone();
                let card = RouterView::new(&card_entry, &latest, locale).allow(&card_role);
                let event = fragment(
                    &format!("router-{}", card_entry.profile.id),
                    &CardFragment {
                        shell: Shell::new(locale, Theme::System),
                        card,
                    },
                );
                Some((event, (updates, holder, false)))
            }
        },
    )
    .boxed()
}

/// An event named `name` carrying the rendered `template`, or a comment when it fails.
pub(crate) fn fragment<T>(name: &str, template: &T) -> Event
where
    T: Template,
{
    match template.render() {
        Ok(html) => Event::default().event(name).data(html),
        Err(error) => {
            tracing::error!(%error, "live fragment failed to render");
            Event::default().comment("render failed")
        }
    }
}

/// An event-stream response that holds `session`'s stream slot while the client listens.
///
/// The stream ends when the session does, when its role changes, and at the session's
/// absolute expiry.
pub(crate) fn guarded<S>(
    events: S,
    session: StreamSession,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>>
where
    S: Stream<Item = Event> + Send + Unpin + 'static,
{
    let held = stream::unfold((events, session), async |(mut source, mut backing)| {
        let event = backing.next_event(&mut source).await?;
        Some((Ok(event), (source, backing)))
    });
    Sse::new(held).keep_alive(KeepAlive::default())
}

/// The header fleet switcher for `entries`, marking `selected`.
pub(crate) fn switcher(entries: &[RegistryEntry], selected: Option<&str>) -> Vec<FleetEntry> {
    entries
        .iter()
        .map(|entry| {
            let id = entry.profile.id.clone();
            let is_selected = selected == Some(id.as_str());
            let name = entry.profile.display_name().to_owned();
            FleetEntry::new(id, name, is_selected)
        })
        .collect()
}

/// The header fleet switcher of a page outside the fleet views: the routers `role` may
/// read, or none when the fleet is not configured or cannot be read.
// cancel-safe: reads only.
pub(crate) async fn masthead(
    state: &WebState,
    role: &Role,
    selected: Option<&str>,
) -> Vec<FleetEntry> {
    let Some(fleet) = state.fleet() else {
        return Vec::new();
    };
    match fleet.visible(role).await {
        Ok(entries) => switcher(&entries, selected),
        Err(error) => {
            tracing::warn!(%error, "fleet switcher could not list routers");
            Vec::new()
        }
    }
}

/// Whether `id` can be a router profile id: what `kcc.toml` names and registry slugs allow.
pub(crate) fn is_profile_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
