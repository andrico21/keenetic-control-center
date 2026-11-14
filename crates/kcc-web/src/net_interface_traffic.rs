//! One interface's live traffic.
//!
//! `GET /ui/sse/r/{router}/network/traffic?name=` reads the router's counters every five
//! seconds while an interface drawer is open and sends the rates; nothing is kept once
//! the drawer closes and the browser stops listening.

use core::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response, sse::Event},
};
use futures_util::{
    StreamExt as _,
    stream::{self, BoxStream},
};
use kcc_domain::{
    RouterCtx,
    interfaces::{self, InterfaceStatistics},
};
use kcc_i18n::locale::Locale;
use kcc_rci::ObjectName;
use serde_json::{Value, json};
use tokio::time::{Instant, MissedTickBehavior, interval};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    dashboard,
    overview::guarded,
    page_kit::{context, request::Params},
    traffic::TrafficSampler,
};

/// Time between two counter readings of an open drawer.
const READING: Duration = Duration::from_secs(5);

/// `GET /ui/sse/r/{router}/network/traffic?name=`: an empty `traffic` event, then one
/// `traffic` event with the interface's rates per counter reading after the first.
pub(crate) async fn stream(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<Vec<(String, String)>>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let Ok(name) = Params::new(query, Vec::new()).object("name") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.status(),
    };
    let Ok((_facts, domain)) = target.context(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Some(permit) = state.streams().try_acquire(&current.stream_key()) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let readings = Readings {
        domain,
        name,
        state: state.clone(),
        locale: user.locale(),
    };
    guarded(readings.events(), permit).into_response()
}

/// What one drawer's stream reads.
struct Readings {
    /// The router.
    domain: RouterCtx,
    /// Interface name.
    name: ObjectName,
    /// Web services, for the clock.
    state: WebState,
    /// The reader's locale.
    locale: Locale,
}

impl Readings {
    /// The opening event, then one event per reading with a rate.
    fn events(self) -> BoxStream<'static, Event> {
        let opening = stream::iter([dashboard::traffic_event(&[], true, self.locale)]);
        let mut ticks = interval(READING);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let points = stream::unfold(
            (self, ticks, TrafficSampler::default()),
            async |(readings, mut clock, mut sampler)| {
                loop {
                    let _: Instant = clock.tick().await;
                    let Some(reading) = readings.reading().await else {
                        continue;
                    };
                    let at = readings.state.unix_seconds();
                    if let Some(point) = sampler.sample(&reading, at, Instant::now()) {
                        let event = dashboard::traffic_event(&[point], false, readings.locale);
                        return Some((event, (readings, clock, sampler)));
                    }
                }
            },
        );
        opening.chain(points).boxed()
    }

    /// The interface's byte counters as a one-entry `show interface stat` map.
    // cancel-safe: a read.
    async fn reading(&self) -> Option<Value> {
        let stats = statistics(&self.domain, &self.name).await?;
        Some(json!({ self.name.as_str(): {"rxbytes": stats.rxbytes, "txbytes": stats.txbytes} }))
    }
}

/// The counters of `name` on the router of `domain`, when reported.
// cancel-safe: a read.
pub(crate) async fn statistics(
    domain: &RouterCtx,
    name: &ObjectName,
) -> Option<InterfaceStatistics> {
    interfaces::read_statistics(domain)
        .await
        .inspect_err(|error| tracing::debug!(%error, "interface counters unavailable"))
        .ok()?
        .remove(name.as_str())
}
