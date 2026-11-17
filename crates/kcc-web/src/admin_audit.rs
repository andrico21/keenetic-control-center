//! The audit log at `/ui/admin/audit` (`ViewAudit`).
//!
//! Every page view verifies the tamper-evident hash chain and states the result; a
//! broken chain still lists what can be read, so the break can be investigated. The
//! entries are filtered by actor, router, action prefix and UTC date range, newest
//! first, and the filtered entries download as JSONL in chain order. Entries carry
//! only the redacted parameters the writers recorded.

mod filter;
pub(crate) mod log;
mod table;

extern crate alloc;

use alloc::sync::Arc;

use askama::Template;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use filter::Filter;
use fluent_bundle::FluentArgs;
use futures_util::stream;
use kcc_app::{audit::AuditEntry, permissions::Role};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use log::{Chain, Log};
use serde::Deserialize;
use serde_json::json;
use tokio::task::JoinError;
use url::form_urlencoded;

use crate::{
    WebState,
    admin_shared::{Change, Tab, TabLink, Timestamp, record, tabs, unavailable},
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::context::Caller,
    table::{pager::Pager, view::TableView},
};

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
    table: TableView,
    /// Table pagination.
    pager: Pager,
    /// The export link with the same filter.
    export: String,
}

localized!(AuditPage);

/// `GET /ui/admin/audit`: chain status, filters and the newest entries.
// cancel-safe: it only reads the audit log; an abandoned blocking read only leaves its result in
// the cache.
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
    let requested = query
        .page
        .as_deref()
        .and_then(|page| page.parse().ok())
        .unwrap_or(1);
    let (rows, pager) = page_rows(&log, &filter, user.role(), locale, requested);
    let date_error = |invalid: bool| {
        if invalid {
            tr(locale, keys::WEB_ADMIN_ERROR_DATE, None)
        } else {
            String::new()
        }
    };
    let page = AuditPage {
        tabs: tabs(user.role(), Tab::Audit),
        chain: chain_text(locale, log.chain()),
        intact: matches!(log.chain(), Chain::Intact(_)),
        export: export_href(&filter),
        from_error: date_error(filter.first_day_invalid()),
        to_error: date_error(filter.last_day_invalid()),
        actor: filter.actor().to_owned(),
        router: filter.router().to_owned(),
        action: filter.action().to_owned(),
        from: filter.first_day().to_owned(),
        to: filter.last_day().to_owned(),
        table: table::entries(&rows, locale),
        pager,
        shell,
    };
    errors::render(&page)
}

/// `GET /ui/admin/audit/export`: the filtered entries as JSONL in chain order.
// NOT cancel-safe: the export's audit entry may be written after the future is dropped.
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
    let shown: Vec<usize> = log
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, entry)| filter.shows(entry, user.role()))
        .map(|(index, _)| index)
        .collect();
    let count = shown.len();
    let params = json!({
        "actor": filter.actor(),
        "router": filter.router(),
        "action": filter.action(),
        "from": filter.first_day(),
        "to": filter.last_day(),
        "entries": count,
    });
    record(
        &state,
        &user,
        Change::done("admin.audit_export", "audit.jsonl", params),
    )
    .await;
    let lines = shown.into_iter().filter_map(move |index| {
        log.entries().get(index).map(|entry| {
            serde_json::to_vec(entry)
                .map(|mut line| {
                    line.push(b'\n');
                    line
                })
                .inspect_err(|error| {
                    tracing::error!(%error, "audit entry could not be serialized");
                })
        })
    });
    let mut response = Body::from_stream(stream::iter(lines)).into_response();
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

/// The verified log, kept while its files do not change; `None` without administration
/// services.
// cancel-safe: the read finishes on a blocking thread and an abandoned call only
// leaves its result in the cache.
async fn read(state: &WebState) -> Option<Result<Arc<Log>, JoinError>> {
    let dir = state.admin()?.state().dir().to_owned();
    Some(state.audit_log().read(dir).await)
}

/// The rows of the requested page of the entries `role` may see and `filter` keeps,
/// newest first; only the shown entries become rows.
fn page_rows(
    log: &Log,
    filter: &Filter,
    role: &Role,
    locale: Locale,
    requested: usize,
) -> (Vec<EntryRow>, Pager) {
    let matching: Vec<&AuditEntry> = log
        .entries()
        .iter()
        .rev()
        .filter(|entry| filter.shows(entry, role))
        .collect();
    let (shown, pager) = Pager::paginate(
        matching,
        requested,
        Tab::Audit.href().to_owned(),
        filter.pairs(),
    );
    let rows = shown
        .into_iter()
        .map(|entry| table::row(entry, locale))
        .collect();
    (rows, pager)
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

#[cfg(test)]
mod tests;
