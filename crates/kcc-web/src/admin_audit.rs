//! The audit log at `/ui/admin/audit` (`ViewAudit`).
//!
//! Every page view verifies the tamper-evident hash chain and states the result; a
//! broken chain still lists what can be read, so the break can be investigated. The
//! entries are filtered by actor, router, action prefix and UTC date range, newest
//! first, and the filtered entries download as JSONL in chain order. Entries carry
//! only the redacted parameters the writers recorded.

use core::time::Duration;
use std::time::UNIX_EPOCH;

use askama::Template;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::audit::{ActorKind, AuditEntry, AuditError, read_entries, verify_chain};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde::Deserialize;
use serde_json::json;
use tokio::task::{JoinError, spawn_blocking};
use url::form_urlencoded;

use crate::{
    WebState,
    admin_shared::{Change, Tab, TabLink, Timestamp, record, tabs, unavailable},
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize, Shell},
    page_kit::context::Caller,
    table::pager::Pager,
};

/// Seconds in a day, the width of one date filter step.
const DAY: Duration = Duration::from_hours(24);

/// The filter query of the page and the export.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditQuery {
    /// Part of the actor's id.
    actor: Option<String>,
    /// Exact router name.
    router: Option<String>,
    /// Start of the action id.
    action: Option<String>,
    /// First UTC day, `YYYY-MM-DD`.
    from: Option<String>,
    /// Last UTC day, `YYYY-MM-DD`.
    to: Option<String>,
    /// Requested page.
    page: Option<String>,
}

/// The validated filter.
#[derive(Debug, Default)]
struct Filter {
    /// Lowercase part of the actor's id; empty matches every actor.
    actor: String,
    /// Exact router name; empty matches every entry.
    router: String,
    /// Start of the action id; empty matches every action.
    action: String,
    /// Earliest Unix time, inclusive.
    from: Option<u64>,
    /// Latest Unix time, inclusive.
    to: Option<u64>,
    /// `from` as typed, `YYYY-MM-DD`.
    from_text: String,
    /// `to` as typed, `YYYY-MM-DD`.
    to_text: String,
    /// Whether `from` could not be read as a date.
    from_invalid: bool,
    /// Whether `to` could not be read as a date.
    to_invalid: bool,
}

impl Filter {
    /// Reads the query; an unreadable date is reported and ignored.
    fn parse(query: &AuditQuery) -> Self {
        let text = |value: Option<&str>| value.unwrap_or_default().trim().to_owned();
        let from_text = text(query.from.as_deref());
        let to_text = text(query.to.as_deref());
        let from = day_start(&from_text);
        let to =
            day_start(&to_text).map(|start| start.saturating_add(DAY.as_secs()).saturating_sub(1));
        Self {
            actor: text(query.actor.as_deref()).to_lowercase(),
            router: text(query.router.as_deref()),
            action: text(query.action.as_deref()),
            from_invalid: !from_text.is_empty() && from.is_none(),
            to_invalid: !to_text.is_empty() && to.is_none(),
            from,
            to,
            from_text,
            to_text,
        }
    }

    /// Whether `entry` passes the filter.
    fn matches(&self, entry: &AuditEntry) -> bool {
        (self.actor.is_empty() || entry.actor.id.to_lowercase().contains(&self.actor))
            && (self.router.is_empty() || entry.router.as_deref() == Some(self.router.as_str()))
            && entry.action.starts_with(&self.action)
            && self.from.is_none_or(|from| entry.ts >= from)
            && self.to.is_none_or(|to| entry.ts <= to)
    }

    /// The filter as query pairs, kept in pagination and export links.
    fn pairs(&self) -> Vec<(String, String)> {
        [
            ("actor", &self.actor),
            ("router", &self.router),
            ("action", &self.action),
            ("from", &self.from_text),
            ("to", &self.to_text),
        ]
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(name, value)| (name.to_owned(), value.clone()))
        .collect()
    }
}

/// The Unix time at 00:00 UTC of `date` (`YYYY-MM-DD`).
fn day_start(date: &str) -> Option<u64> {
    let valid = date.len() == 10
        && date.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_digit() || (byte == b'-' && (index == 4 || index == 7))
        });
    if !valid {
        return None;
    }
    humantime::parse_rfc3339(&format!("{date}T00:00:00Z"))
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|since| since.as_secs())
}

/// The state of the hash chain.
enum Chain {
    /// Every entry verified.
    Intact(usize),
    /// The chain breaks at this sequence number.
    Broken(u64),
    /// The log could not be read.
    Unreadable,
}

/// The audit log read for one request.
struct Log {
    /// Chain verification result.
    chain: Chain,
    /// Every readable entry, in chain order.
    entries: Vec<AuditEntry>,
}

/// One entry row.
struct EntryRow {
    /// When it happened.
    time: Option<Timestamp>,
    /// Actor id.
    actor: String,
    /// Actor front-end.
    kind: MessageKey,
    /// Action id.
    action: String,
    /// Router name.
    router: String,
    /// Target.
    target: String,
    /// Outcome id.
    outcome: String,
    /// Redacted parameters as JSON, empty when none.
    params: String,
}

/// The audit page.
#[derive(Template)]
#[template(path = "pages/admin_audit.html")]
struct AuditPage {
    /// Page shell.
    shell: Shell,
    /// Administration tabs.
    tabs: Vec<TabLink>,
    /// The chain status sentence.
    chain: String,
    /// Whether the chain verified.
    intact: bool,
    /// The filter as submitted.
    actor: String,
    /// Router filter.
    router: String,
    /// Action filter.
    action: String,
    /// From date.
    from: String,
    /// To date.
    to: String,
    /// From-date error.
    from_error: String,
    /// To-date error.
    to_error: String,
    /// The shown page of entries.
    rows: Vec<EntryRow>,
    /// Table pagination.
    pager: Pager,
    /// The export link with the same filter.
    export: String,
}

impl Localize for AuditPage {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

/// `GET /ui/admin/audit`: chain status, filters and the newest entries.
pub(crate) async fn page(
    State(state): State<WebState>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Admin, None)
        .await;
    let log = match read(&state).await {
        Some(Ok(log)) => log,
        Some(Err(error)) => return errors::internal(&error, shell),
        None => return unavailable(Some(shell)),
    };
    let filter = Filter::parse(&query);
    let locale = user.locale();
    let mut matching: Vec<AuditEntry> = log
        .entries
        .into_iter()
        .filter(|entry| filter.matches(entry))
        .collect();
    matching.reverse();
    let requested = query
        .page
        .as_deref()
        .and_then(|page| page.parse().ok())
        .unwrap_or(1);
    let all = matching.into_iter().map(row).collect();
    let (rows, pager) =
        Pager::paginate(all, requested, Tab::Audit.href().to_owned(), filter.pairs());
    let date_error = |invalid: bool| {
        if invalid {
            tr(locale, keys::WEB_ADMIN_ERROR_DATE, None)
        } else {
            String::new()
        }
    };
    let page = AuditPage {
        tabs: tabs(user.role(), Tab::Audit),
        chain: chain_text(locale, &log.chain),
        intact: matches!(log.chain, Chain::Intact(_)),
        export: export_href(&filter),
        from_error: date_error(filter.from_invalid),
        to_error: date_error(filter.to_invalid),
        actor: filter.actor,
        router: filter.router,
        action: filter.action,
        from: filter.from_text,
        to: filter.to_text,
        rows,
        pager,
        shell,
    };
    errors::render(&page)
}

/// `GET /ui/admin/audit/export`: the filtered entries as JSONL in chain order.
pub(crate) async fn export(
    State(state): State<WebState>,
    Query(query): Query<AuditQuery>,
    user: CurrentUser,
) -> Response {
    let log = match read(&state).await {
        Some(Ok(log)) => log,
        Some(Err(error)) => {
            tracing::error!(%error, "audit export failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        None => return unavailable(None),
    };
    let filter = Filter::parse(&query);
    let mut body = String::new();
    let mut count = 0_usize;
    for entry in log.entries.iter().filter(|entry| filter.matches(entry)) {
        match serde_json::to_string(entry) {
            Ok(line) => {
                body.push_str(&line);
                body.push('\n');
                count = count.saturating_add(1);
            }
            Err(error) => {
                tracing::error!(%error, "audit entry could not be serialized");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }
    let params = json!({
        "actor": filter.actor,
        "router": filter.router,
        "action": filter.action,
        "from": filter.from_text,
        "to": filter.to_text,
        "entries": count,
    });
    record(
        &state,
        &user,
        Change::done("admin.audit_export", "audit.jsonl", params),
    )
    .await;
    let mut response = body.into_response();
    let headers = response.headers_mut();
    drop(headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson; charset=utf-8"),
    ));
    drop(headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"kcc-audit.jsonl\""),
    ));
    response
}

/// Verifies the chain and reads the entries off the async executor; `None` without
/// administration services.
async fn read(state: &WebState) -> Option<Result<Log, JoinError>> {
    let dir = state.admin()?.state().dir().to_owned();
    Some(
        spawn_blocking(move || match verify_chain(&dir) {
            Ok(entries) => Log {
                chain: Chain::Intact(entries.len()),
                entries,
            },
            Err(AuditError::Chain { seq }) => Log {
                chain: Chain::Broken(seq),
                entries: read_entries(&dir).unwrap_or_else(|error| {
                    tracing::error!(%error, "entries of the broken audit log could not be read");
                    Vec::new()
                }),
            },
            Err(error) => {
                tracing::error!(%error, "audit log could not be read");
                Log {
                    chain: Chain::Unreadable,
                    entries: Vec::new(),
                }
            }
        })
        .await,
    )
}

/// The table row of `entry`.
fn row(entry: AuditEntry) -> EntryRow {
    let params = if entry.params_redacted.is_null() {
        String::new()
    } else {
        entry.params_redacted.to_string()
    };
    EntryRow {
        time: Timestamp::at(entry.ts),
        kind: match entry.actor.kind {
            ActorKind::Web => keys::WEB_ADMIN_AUDIT_KIND_WEB,
            ActorKind::Mcp => keys::WEB_ADMIN_AUDIT_KIND_MCP,
            ActorKind::Cli => keys::WEB_ADMIN_AUDIT_KIND_CLI,
            ActorKind::System | _ => keys::WEB_ADMIN_AUDIT_KIND_SYSTEM,
        },
        actor: entry.actor.id,
        action: entry.action,
        router: entry.router.unwrap_or_default(),
        target: entry.target.unwrap_or_default(),
        outcome: entry.outcome,
        params,
    }
}

/// The chain status sentence in `locale`.
fn chain_text(locale: Locale, chain: &Chain) -> String {
    match *chain {
        Chain::Intact(count) => {
            let mut args = FluentArgs::new();
            args.set("count", count);
            tr(locale, keys::WEB_ADMIN_AUDIT_INTACT, Some(&args))
        }
        Chain::Broken(seq) => {
            let mut args = FluentArgs::new();
            args.set("value", seq.to_string());
            tr(locale, keys::WEB_ADMIN_AUDIT_BROKEN, Some(&args))
        }
        Chain::Unreadable => tr(locale, keys::WEB_ADMIN_AUDIT_UNREADABLE, None),
    }
}

/// The export link with the filter's query.
fn export_href(filter: &Filter) -> String {
    let pairs = filter.pairs();
    if pairs.is_empty() {
        return "/ui/admin/audit/export".to_owned();
    }
    let query: String = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish();
    format!("/ui/admin/audit/export?{query}")
}
