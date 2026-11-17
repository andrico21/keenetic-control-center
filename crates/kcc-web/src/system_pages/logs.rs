//! The router log at `/ui/r/{router}/system/logs`: its latest lines, filtered by a text,
//! followed live, and downloadable as text.
//!
//! The page reads the log through `log_source`; the live stream opens with the current
//! lines (replacing the page's, so nothing between the page and the stream is lost), then
//! sends each batch of new lines. A filter applies to both. Downloads are audited.

use core::future::ready;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse as _, Response, sse::Event},
};
use futures_util::{
    StreamExt as _,
    stream::{self, BoxStream},
};
use kcc_i18n::{bundle::MessageKey, keys, locale::Locale};

use super::{
    log_source::source,
    shared::{Visit, value},
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    overview::{fragment, guarded},
    page::{Localize as _, Shell},
    page_kit::{
        audit::Record,
        context::{self, fragment_shell},
        request::with_query,
        respond,
    },
    stream_session::StreamSession,
};

/// Longest filter text, in characters.
const FILTER_CHARS: usize = 100;

/// The page.
#[derive(Template)]
#[template(path = "pages/system_logs.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why the log could not be read.
    problem: Option<MessageKey>,
    /// The filter text; empty for none.
    filter: String,
    /// The latest lines matching the filter.
    lines: Vec<String>,
    /// The live stream's URL.
    stream: String,
}

localized!(Page);

/// Log lines sent by the stream: the whole list (`tail`) or new items (`lines`).
#[derive(Template)]
#[template(path = "partials/system_log_lines.html")]
struct LinesView {
    /// Locale carrier.
    shell: Shell,
    /// The lines.
    lines: Vec<String>,
    /// Whether this is the whole list, which replaces the page's.
    whole: bool,
}

localized!(LinesView);

/// The filter text of a query, trimmed and cut to [`FILTER_CHARS`].
fn filter_of(query: &[(String, String)]) -> String {
    value(query, "q")
        .unwrap_or_default()
        .chars()
        .take(FILTER_CHARS)
        .collect()
}

/// The `lines` that contain `filter`, without regard to case; all when it is empty.
fn matching(lines: Vec<String>, filter: &str) -> Vec<String> {
    let needle = filter.to_lowercase();
    lines
        .into_iter()
        .filter(|line| needle.is_empty() || line.to_lowercase().contains(&needle))
        .collect()
}

/// `GET /ui/r/{router}/system/logs[?q=]`: the latest lines and the live stream.
// NOT cancel-safe: it only reads router state to render the page, but it may sign in first, and a
// sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(query): Form<Vec<(String, String)>>,
) -> Response {
    let (shell, reading) = match Visit::new(&headers, &current, &user)
        .open(&state, &router)
        .await
    {
        Ok(opened) => opened,
        Err(refusal) => return refusal.into_response(),
    };
    let filter = filter_of(&query);
    let base = format!("/ui/sse/r/{router}/system/logs");
    let stream = if filter.is_empty() {
        base
    } else {
        with_query(&base, &[("q", &filter)])
    };
    let (lines, problem) = match reading {
        Ok((_, domain)) => match source(&state, &router).tail(domain).await {
            Ok(found) => (matching(found, &filter), None),
            Err(error) => {
                tracing::warn!(%error, "router log could not be read");
                (Vec::new(), Some(keys::WEB_SYSTEM_READ_FAILED))
            }
        },
        Err(message) => (Vec::new(), Some(message)),
    };
    errors::render(&Page {
        shell,
        tabs: TabBar::new(router.clone(), Tab::Logs),
        router,
        problem,
        filter,
        lines,
        stream,
    })
}

/// `GET /ui/sse/r/{router}/system/logs[?q=]`: the current lines, then each batch of new
/// ones, filtered.
// NOT cancel-safe: it only detects the router before returning the log stream, but it may sign in
// first, and a sign-in dropped mid-way can leave an orphaned router session.
pub(crate) async fn stream(
    State(state): State<WebState>,
    Path(router): Path<String>,
    current: CurrentSession,
    user: CurrentUser,
    Form(query): Form<Vec<(String, String)>>,
) -> Response {
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.status(),
    };
    let Some(slot) = StreamSession::open(&state, &current, &user) else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let Ok((_, domain)) = target.context(&state).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let filter = filter_of(&query);
    let locale = user.locale();
    let log = source(&state, &router);
    let seen = log.tail(domain.clone()).await.unwrap_or_default();
    let opening = view(matching(seen.clone(), &filter), true, locale);
    let follow = log
        .follow(domain, seen)
        .filter_map(move |batch| {
            let fresh = matching(batch, &filter);
            ready((!fresh.is_empty()).then(|| view(fresh, false, locale)))
        })
        .boxed();
    let events: BoxStream<'static, _> = stream::iter([opening]).chain(follow).boxed();
    guarded(events, slot).into_response()
}

/// The stream event of `lines`: the whole list, or new items.
fn view(lines: Vec<String>, whole: bool, locale: Locale) -> Event {
    let name = if whole { "tail" } else { "lines" };
    fragment(
        name,
        &LinesView {
            shell: fragment_shell(locale),
            lines,
            whole,
        },
    )
}

/// `GET /ui/r/{router}/system/logs/download`: the latest lines as a text file.
// NOT cancel-safe: the download's audit entry may be written after the future is dropped.
pub(crate) async fn download(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Response {
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.status(),
    };
    let record = Record::on_router("web.log_download", &router, "show log".to_owned());
    let read = match target.context(&state).await {
        Ok((_, domain)) => source(&state, &router).tail(domain).await.ok(),
        Err(_unreachable) => None,
    };
    let Some(lines) = read else {
        record.append(&state, &user, "unreachable").await;
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    record.append(&state, &user, "success").await;
    let mut text = lines.join("\n");
    text.push('\n');
    respond::attachment(
        text,
        "text/plain; charset=utf-8",
        &format!("{router}-log.txt"),
    )
}
