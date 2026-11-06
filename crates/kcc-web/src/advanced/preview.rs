//! The explorer's request preview, the router's stored lines for a command (from its
//! running configuration, secrets redacted), and the download of the last response too
//! large for its page.

use core::str;

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_catalog::Catalog;
use kcc_config::{
    config_text::{CliLine, Token, flatten, parse},
    secrets::redact,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;

use super::{
    check::{Problem, sentence},
    context::{self, fragment_shell},
    explorer::PageQuery,
    lookup::{clip, facts_for, notice},
    request,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page::{Localize, Shell},
};

/// Stored lines shown at most.
const STORED_LINES: usize = 50;

/// The request preview.
#[derive(Template)]
#[template(path = "partials/explorer_preview.html")]
struct PreviewView {
    /// Locale carrier.
    shell: Shell,
    /// HTTP method.
    method: &'static str,
    /// Endpoint path.
    endpoint: String,
    /// Pretty JSON payload, secrets masked.
    payload: String,
    /// Why the request would not be sent.
    problems: Vec<String>,
}

/// The router's stored lines of one command.
#[derive(Template)]
#[template(path = "partials/explorer_stored.html")]
struct StoredView {
    /// Locale carrier.
    shell: Shell,
    /// Matching lines, secrets redacted.
    lines: Vec<String>,
    /// Localized count of lines left out, empty when none.
    more: String,
}

impl Localize for PreviewView {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Localize for StoredView {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// `POST /ui/r/{router}/explorer/preview`: the method, endpoint and JSON the form would
/// send, with the validation result. Nothing is sent to the router.
pub(crate) async fn preview(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let (_, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let locale = user.locale();
    let view = match request::build(facts.catalog(), &pairs) {
        Ok(built) => {
            let (method, endpoint, payload) = built.wire();
            PreviewView {
                shell: fragment_shell(locale),
                method,
                endpoint,
                payload: serde_json::to_string_pretty(&payload).unwrap_or_default(),
                problems: Vec::new(),
            }
        }
        Err(problems) => PreviewView {
            shell: fragment_shell(locale),
            method: "POST",
            endpoint: String::new(),
            payload: String::new(),
            problems: problems
                .iter()
                .map(|problem: &Problem| sentence(locale, problem))
                .collect(),
        },
    };
    errors::render(&view)
}

/// `GET /ui/r/{router}/explorer/stored?path=`: the running-configuration lines of one
/// command, which show how the router stores it.
pub(crate) async fn stored(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(query): Form<PageQuery>,
) -> Response {
    let (target, facts) = match facts_for(&state, &user, &router).await {
        Ok(found) => found,
        Err(response) => return *response,
    };
    let locale = user.locale();
    let path = clip(query.path());
    if facts.catalog().lookup(path).is_none() {
        return notice(locale, "error", keys::WEB_EXPLORER_UNKNOWN_COMMAND);
    }
    let client = match target.fleet().registry().client(target.router()).await {
        Ok(found) => found,
        Err(error) => {
            tracing::warn!(%error, "stored lines: no router client");
            return notice(locale, "error", keys::WEB_EXPLORER_UNREACHABLE);
        }
    };
    let lines = match client.download_config(ConfigKind::Running).await {
        Ok(bytes) => str::from_utf8(bytes.expose_secret())
            .ok()
            .and_then(|text| parse(text).ok())
            .map(|ast| matching_lines(facts.catalog(), &flatten(&redact(&ast)), path)),
        Err(error) => {
            tracing::warn!(?error, "stored lines: running configuration unavailable");
            return notice(locale, "error", keys::WEB_EXPLORER_UNREACHABLE);
        }
    };
    let Some(all) = lines else {
        return notice(locale, "error", keys::WEB_EXPLORER_FAILED);
    };
    errors::render(&stored_view(all, locale))
}

/// `GET /ui/r/{router}/explorer/response`: the last response of this session on this
/// router that was too large for its page.
pub(crate) async fn download(
    State(state): State<WebState>,
    Path(router): Path<String>,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    if let Err(refusal) = context::target(&state, &user, &router).await {
        return refusal.status();
    }
    let Some((body, json)) = state.advanced().response(&current.stream_key(), &router) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    attachment(&router, &body, json)
}

/// The stored-lines view of `all`, showing the first [`STORED_LINES`].
fn stored_view(all: Vec<String>, locale: Locale) -> StoredView {
    let hidden = all.len().saturating_sub(STORED_LINES);
    let more = if hidden > 0 {
        let mut args = FluentArgs::new();
        args.set("count", hidden);
        tr(locale, keys::WEB_EXPLORER_STORED_MORE, Some(&args))
    } else {
        String::new()
    };
    StoredView {
        shell: fragment_shell(locale),
        lines: all.into_iter().take(STORED_LINES).collect(),
        more,
    }
}

/// The flattened lines whose command is `path`: of every catalog command whose words
/// occur in order in a line, the longest one owns the line.
fn matching_lines(catalog: &Catalog, lines: &[CliLine], path: &str) -> Vec<String> {
    let wanted: Vec<&str> = path.split_whitespace().collect();
    let Some(first) = wanted.first() else {
        return Vec::new();
    };
    let candidates: Vec<Vec<&str>> = catalog
        .commands()
        .map(|command| command.path.split_whitespace().collect::<Vec<_>>())
        .filter(|words| words.first() == Some(first))
        .collect();
    lines
        .iter()
        .filter(|line| {
            let words = words_of(line);
            let positive = words.strip_prefix(&["no"]).unwrap_or(&words);
            positive.first() == Some(first)
                && candidates
                    .iter()
                    .filter(|candidate| in_order(candidate, positive))
                    .max_by_key(|candidate| candidate.len())
                    .is_some_and(|owner| *owner == wanted)
        })
        .map(|line| ns3_redacted(line).to_string())
        .collect()
}

/// The plain words of a line; an `ns3` token counts as one word.
fn words_of(line: &CliLine) -> Vec<&str> {
    line.tokens
        .iter()
        .map(|token| match token {
            Token::Word(word) => word.as_str(),
            Token::Ns3(_) | _ => "ns3",
        })
        .collect()
}

/// Whether every word of `needle` occurs in `haystack` in order.
fn in_order(needle: &[&str], haystack: &[&str]) -> bool {
    let mut rest = haystack.iter();
    needle
        .iter()
        .all(|word| rest.any(|candidate| candidate == word))
}

/// `line` with every `ns3` payload replaced, whatever the secret registry knows.
fn ns3_redacted(line: &CliLine) -> CliLine {
    let mut copy = line.clone();
    for token in &mut copy.tokens {
        if matches!(token, Token::Ns3(_)) {
            *token = Token::Ns3("<redacted>".to_owned());
        }
    }
    copy
}

/// `body` as a file download named after `router`.
fn attachment(router: &str, body: &str, json: bool) -> Response {
    let (content_type, extension) = if json {
        ("application/json", "json")
    } else {
        ("text/plain; charset=utf-8", "txt")
    };
    let disposition = format!("attachment; filename=\"kcc-{router}-response.{extension}\"");
    let mut response = (StatusCode::OK, body.to_owned()).into_response();
    let headers = response.headers_mut();
    drop(headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type)));
    if let Ok(value) = HeaderValue::from_str(&disposition) {
        drop(headers.insert(header::CONTENT_DISPOSITION, value));
    }
    response
}
