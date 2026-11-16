//! The live progress of an apply: `GET {PREFIX}/{id}/events`.
//!
//! Every setting the job sent so far (so a reload replays them), then each new one and
//! the share sent; a heartbeat every 10 seconds tells how long the router's fail-safe
//! timer still runs. `end` brings the result and `done` closes the stream once the job
//! ended and its end is recorded; without an apply kcc runs (kcc restarted meanwhile) the
//! recorded end comes at once. `?view=countdown` sends the heartbeat only, for the
//! results step, and `done` once the timer ran out.
//!
//! [`Feed`] is the stream itself; each wizard names its own recorded end.

use alloc::sync::Arc;
use core::{pin::pin, time::Duration};

use axum::{
    Extension,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse as _, Response, sse::Event},
};
use futures_util::{
    StreamExt as _,
    future::{self, Either},
    stream::{self, BoxStream},
};
use kcc_i18n::locale::Locale;
use serde::Deserialize;
use tokio::{
    sync::watch,
    time::{Instant, Interval, MissedTickBehavior, interval},
};

use super::{
    beats,
    finishing::Finishing,
    live::{Live, Progress},
    service::Wizards,
    services::Services,
    visit::Visit,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    overview::guarded,
    stream_session::StreamSession,
};

/// How often the heartbeat tells the timer.
const HEARTBEAT: Duration = Duration::from_secs(10);

/// The stream's view.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct View {
    /// `countdown` for the heartbeat only.
    #[serde(default)]
    view: Option<String>,
}

impl View {
    /// Whether the stream sends the heartbeat only.
    pub(crate) fn countdown(&self) -> bool {
        self.view.as_deref() == Some("countdown")
    }
}

/// The `end` and `done` events from a wizard's recorded end.
pub(crate) type Ending = Box<dyn Fn() -> [Event; 2] + Send>;

/// What a stream knows of the apply it follows.
pub(crate) struct Feed {
    /// The apply, when kcc runs it.
    live: Option<Arc<Live>>,
    /// When the apply started, and the fail-safe timer's length in seconds.
    timer: (u64, u64),
    /// The listener's locale.
    locale: Locale,
    /// The Web UI, for the time.
    state: WebState,
    /// The recorded end, read when the stream ends.
    ending: Ending,
}

impl Feed {
    /// The stream in `locale` of an apply: `live` while kcc runs it, under the fail-safe
    /// `timer` (its start and length in seconds), ending with what `ending` reads.
    pub(crate) fn new(
        state: &WebState,
        locale: Locale,
        (live, timer): (Option<Arc<Live>>, (u64, u64)),
        ending: Ending,
    ) -> Self {
        Self {
            live,
            timer,
            locale,
            state: state.clone(),
            ending,
        }
    }

    /// The stream's events from the start of the apply; the heartbeat only when
    /// `countdown`.
    pub(crate) fn stream(self, countdown: bool) -> BoxStream<'static, Event> {
        Cursor::new(self, countdown).stream()
    }
}

/// `GET {PREFIX}/{id}/events`: the apply's progress.
// cancel-safe: reads only; the returned stream owns its state.
pub(crate) async fn events<F>(
    State(state): State<WebState>,
    Path(id): Path<String>,
    Query(view): Query<View>,
    Extension(wizards): Extension<Arc<Wizards<F>>>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response
where
    F: Finishing,
{
    let services = match Services::of(&state, &user) {
        Ok(found) => found,
        Err(refusal) => return refusal.status(),
    };
    let visit = match Visit::open(services, &wizards, &id).await {
        Ok(found) => found,
        Err(refusal) => return refusal.status(),
    };
    let Some(run) = visit.record().run() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(slot) = StreamSession::open(&state, &current, &user) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let store = services.store();
    let locale = user.locale();
    let ending: Ending = Box::new(move || {
        let ended = store
            .load::<F>(&id)
            .ok()
            .flatten()
            .and_then(|record| record.run()?.ended().cloned());
        beats::closing(
            locale,
            format!("{}/{id}/results", F::PREFIX),
            F::ended_words(ended.as_ref(), locale),
        )
    });
    let apply = (
        visit.session().live(),
        (run.started_at(), run.safety_seconds()),
    );
    drop(visit);
    let feed = Feed::new(&state, locale, apply, ending);
    guarded(feed.stream(view.countdown()), slot).into_response()
}

/// Where a stream is.
struct Cursor {
    /// The apply it follows.
    source: Feed,
    /// Its progress, when kcc runs it.
    progress: Option<watch::Receiver<Progress>>,
    /// Settings sent so far.
    sent: usize,
    /// The heartbeat; its first tick comes at once.
    ticks: Interval,
    /// Whether the heartbeat is all it sends.
    countdown: bool,
}

impl Cursor {
    /// A stream of `source` from its start.
    fn new(source: Feed, countdown: bool) -> Self {
        let mut ticks = interval(HEARTBEAT);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            progress: source.live.as_ref().map(|live| live.watch()),
            source,
            sent: 0,
            ticks,
            countdown,
        }
    }

    /// The stream's events, round by round, until it closes.
    fn stream(self) -> BoxStream<'static, Event> {
        stream::unfold(Some(self), async |held| {
            let mut cursor = held?;
            let beat = cursor.wait().await;
            let (out, open) = cursor.round(beat);
            Some((stream::iter(out), open.then_some(cursor)))
        })
        .flatten()
        .boxed()
    }

    /// Waits for the progress to change or the heartbeat to be due; whether it is due.
    // cancel-safe: the tick and the change notification are both cancel-safe.
    async fn wait(&mut self) -> bool {
        let closed = match self.progress.as_mut() {
            Some(progress) if !self.countdown => {
                let tick = pin!(self.ticks.tick());
                let change = pin!(progress.changed());
                match future::select(tick, change).await {
                    Either::Left(_) => return true,
                    Either::Right((changed, _)) => changed.is_err(),
                }
            }
            Some(_) | None => {
                let _: Instant = self.ticks.tick().await;
                return true;
            }
        };
        if closed {
            self.progress = None;
        }
        false
    }

    /// The events of one round, with the heartbeat when `beat`, and whether the stream
    /// stays open.
    fn round(&mut self, beat: bool) -> (Vec<Event>, bool) {
        let source = &self.source;
        let locale = source.locale;
        let snapshot = self
            .progress
            .as_mut()
            .map(|progress| progress.borrow_and_update().clone());
        let active = snapshot
            .as_ref()
            .map_or(source.timer.0, Progress::active_at);
        let now = source.state.unix_seconds();
        let (heartbeat, ticking) = beats::heartbeat(locale, (active, source.timer.1), now);
        let mut out = Vec::new();
        if beat {
            out.push(heartbeat);
        }
        if self.countdown {
            if !ticking {
                out.push(beats::done());
            }
            return (out, ticking);
        }
        let Some(progress) = snapshot else {
            out.extend((source.ending)());
            return (out, false);
        };
        for sent in progress.sent().iter().skip(self.sent) {
            let text = source
                .live
                .as_ref()
                .and_then(|live| live.text(sent.index()).cloned())
                .unwrap_or_default();
            out.push(beats::line(locale, text, sent.outcome()));
        }
        self.sent = progress.sent().len();
        out.push(beats::bar(locale, progress.percent()));
        if progress.finished() {
            out.extend((source.ending)());
            return (out, false);
        }
        (out, true)
    }
}
