//! The router dashboard at `/ui/r/{router}` and its live stream at
//! `/ui/sse/r/{router}/traffic`.
//!
//! The stream opens with the traffic history (`traffic`, JSON, at most 30 minutes) and then
//! sends, after every poll, the re-rendered live region (`live`, HTML) and the new traffic
//! point (`traffic`). The browser never contacts the router; it only listens to kcc.

extern crate alloc;

use alloc::sync::Arc;

use askama::Template;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Redirect, Response, sse::Event},
};
use fluent_bundle::FluentArgs;
use futures_util::{
    StreamExt as _,
    stream::{self, BoxStream},
};
use kcc_app::{permissions::Role, registry::RegistryEntry};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    format, keys,
    locale::Locale,
};
use serde_json::json;

use crate::{
    WebState, authz,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    fleet::UpdateStatus,
    nav::Section,
    overview::{FIRST_POLL_WAIT, fragment, guarded, switcher},
    page::{Localize as _, Shell, Theme},
    prefs,
    stream_session::StreamSession,
    telemetry::Feed,
    traffic::TrafficPoint,
    view::RouterView,
};

/// Where the supported firmware lines are documented.
const FIRMWARE_DOC: &str = concat!(env!("CARGO_PKG_REPOSITORY"), "/blob/HEAD/docs/FIRMWARE.md");

/// The bit-rate units of the chart axis, smallest first.
const RATE_UNITS: [MessageKey; 4] = [
    keys::COMMON_UNIT_BITS,
    keys::COMMON_UNIT_KILOBITS,
    keys::COMMON_UNIT_MEGABITS,
    keys::COMMON_UNIT_GIGABITS,
];

/// The dashboard page.
#[derive(Template)]
#[template(path = "pages/dashboard.html")]
struct DashboardPage {
    /// Page shell.
    shell: Shell,
    /// The router.
    router: RouterView,
    /// Firmware-update status.
    update: UpdateBadge,
    /// Backups page link, when the role may open it.
    backups: Option<&'static str>,
    /// Supported firmware documentation.
    firmware_doc: &'static str,
    /// Chart axis unit patterns as a JSON array, `{}` standing for the number.
    units: String,
    /// The live stream URL.
    stream: String,
    /// Whether the live region carries out-of-band header updates (stream only).
    oob: bool,
}

localized!(DashboardPage);

/// The live region, sent by the stream.
#[derive(Template)]
#[template(path = "partials/router_live.html")]
struct LiveFragment {
    /// Locale carrier.
    shell: Shell,
    /// The router.
    router: RouterView,
    /// Firmware-update status.
    update: UpdateBadge,
    /// Backups page link, when the role may open it.
    backups: Option<&'static str>,
    /// Always true: the header status pill follows the region.
    oob: bool,
}

localized!(LiveFragment);

/// The firmware-update line of the system panel.
struct UpdateBadge {
    /// Whether newer firmware is available, which shows the line as a badge.
    available: bool,
    /// The localized line.
    text: String,
}

impl UpdateBadge {
    /// The line for `status` in `locale`.
    fn new(status: &UpdateStatus, locale: Locale) -> Self {
        match status {
            UpdateStatus::Available { version } => {
                let mut args = FluentArgs::new();
                args.set("version", version.clone());
                Self {
                    available: true,
                    text: tr(locale, keys::WEB_UPDATE_AVAILABLE, Some(&args)),
                }
            }
            UpdateStatus::Current => Self {
                available: false,
                text: tr(locale, keys::WEB_UPDATE_CURRENT, None),
            },
            UpdateStatus::Unknown => Self {
                available: false,
                text: tr(locale, keys::WEB_UPDATE_UNKNOWN, None),
            },
        }
    }

    /// Whether newer firmware is available.
    const fn available(&self) -> bool {
        self.available
    }

    /// The localized line.
    fn text(&self) -> &str {
        &self.text
    }
}

/// What the stream needs to re-render the live region.
struct LiveContext {
    /// The router profile.
    entry: RegistryEntry,
    /// Viewer locale.
    locale: Locale,
    /// Viewer role.
    role: Role,
    /// Backups link.
    backups: Option<&'static str>,
    /// Services, for the update status.
    state: WebState,
}

/// `GET /ui/r/{router}`: the dashboard of one router.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = prefs::shell_for_locale(&headers, user.locale())
        .with_csrf_token(current.session().csrf_token().to_owned())
        .with_section(Section::Dashboard);
    let Some(fleet) = state.fleet() else {
        return Redirect::to(Section::Dashboard.href()).into_response();
    };
    let entries = match fleet.visible(user.role()).await {
        Ok(entries) => entries,
        Err(error) => return errors::internal(&error, shell),
    };
    let Some(entry) = entries.iter().find(|entry| entry.profile.id == router) else {
        return errors::response(Kind::NotFound, shell);
    };
    let feed = fleet.telemetry().feed(&router).await;
    let live = feed.first(FIRST_POLL_WAIT).await;
    let view = RouterView::new(entry, &live, user.locale()).allow(user.role());
    let status = view.status();
    errors::render(&DashboardPage {
        shell: shell.with_fleet(switcher(&entries, Some(&router)), Some(status)),
        update: UpdateBadge::new(&fleet.update_status(&router), user.locale()),
        backups: backups(user.role()),
        firmware_doc: FIRMWARE_DOC,
        units: units(user.locale()),
        stream: format!("/ui/sse/r/{router}/traffic"),
        oob: false,
        router: view,
    })
}

/// `GET /ui/sse/r/{router}/traffic`: the traffic history, then the live region and the
/// newest traffic point after every poll.
pub(crate) async fn stream(
    State(state): State<WebState>,
    Path(router): Path<String>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let Some(fleet) = state.fleet() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(slot) = StreamSession::open(&state, &current, &user) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let found = match fleet.visible(user.role()).await {
        Ok(entries) => entries.into_iter().find(|entry| entry.profile.id == router),
        Err(error) => {
            tracing::error!(%error, "dashboard stream could not list routers");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let Some(entry) = found else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let feed = fleet.telemetry().feed(&router).await;
    let history = fleet.telemetry().history(&router);
    let context = LiveContext {
        entry,
        locale: user.locale(),
        role: user.role().clone(),
        backups: backups(user.role()),
        state: state.clone(),
    };
    guarded(live_events(context, feed, &history), slot).into_response()
}

/// The dashboard events: the history first, then one live region (and traffic point)
/// per poll.
fn live_events(
    context: LiveContext,
    feed: Arc<Feed>,
    history: &[TrafficPoint],
) -> BoxStream<'static, Event> {
    let opening = stream::iter([traffic_event(history, true, context.locale)]);
    let watcher = feed.subscribe();
    let updates = stream::unfold(
        (watcher, feed, context, true),
        async |(mut updates, holder, scope, first)| {
            if !(first && updates.borrow_and_update().polled()) {
                updates.changed().await.ok()?;
            }
            let latest = updates.borrow_and_update().clone();
            let router = RouterView::new(&scope.entry, &latest, scope.locale).allow(&scope.role);
            let status = scope.state.fleet().map_or(UpdateStatus::Unknown, |fleet| {
                fleet.update_status(&scope.entry.profile.id)
            });
            let mut events = vec![fragment(
                "live",
                &LiveFragment {
                    shell: Shell::new(scope.locale, Theme::System),
                    router,
                    update: UpdateBadge::new(&status, scope.locale),
                    backups: scope.backups,
                    oob: true,
                },
            )];
            if let Some(point) = latest.point().filter(|_| !first) {
                events.push(traffic_event(&[point], false, scope.locale));
            }
            Some((stream::iter(events), (updates, holder, scope, false)))
        },
    )
    .flatten();
    opening.chain(updates).boxed()
}

/// A `traffic` event: the points as uPlot columns plus the newest rates as text.
pub(crate) fn traffic_event(points: &[TrafficPoint], replace: bool, locale: Locale) -> Event {
    let latest = points.last();
    let payload = json!({
        "replace": replace,
        "t": points.iter().map(|point| point.at()).collect::<Vec<_>>(),
        "rx": points.iter().map(|point| point.rx()).collect::<Vec<_>>(),
        "tx": points.iter().map(|point| point.tx()).collect::<Vec<_>>(),
        "rx_text": latest.map(|point| format::bit_rate(locale, point.rx())),
        "tx_text": latest.map(|point| format::bit_rate(locale, point.tx())),
    });
    Event::default().event("traffic").data(payload.to_string())
}

/// The chart axis units of `locale` as a JSON array of patterns, `{}` standing for the
/// number.
pub(crate) fn units(locale: Locale) -> String {
    let patterns: Vec<String> = RATE_UNITS
        .iter()
        .map(|key| {
            let mut args = FluentArgs::new();
            args.set("value", "{}");
            tr(locale, *key, Some(&args))
        })
        .collect();
    json!(patterns).to_string()
}

/// The backups link, when `role` may open it.
fn backups(role: &Role) -> Option<&'static str> {
    let href = Section::Configuration.href();
    authz::permits(role, href).then_some(href)
}
