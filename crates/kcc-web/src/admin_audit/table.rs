//! The audit table: when, who, what, where, the outcome, and the redacted parameters.

use kcc_app::audit::{ActorKind, AuditEntry};
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::EntryRow;
use crate::{
    admin_shared::Timestamp,
    table::{
        cells::Cell,
        head::Head,
        piece::{Line, Piece},
        view::TableView,
    },
};

/// The table of `rows` in `locale`, or a note in its place when there is none.
pub(super) fn entries(rows: &[EntryRow], locale: Locale) -> TableView {
    let mut view = TableView::new("table audit-table");
    if rows.is_empty() {
        return view.blank("page__text", tr(locale, keys::WEB_ADMIN_AUDIT_EMPTY, None));
    }
    for key in [
        keys::WEB_ADMIN_AUDIT_TIME,
        keys::WEB_ADMIN_AUDIT_ACTOR,
        keys::WEB_ADMIN_AUDIT_ACTION,
        keys::WEB_ADMIN_AUDIT_ROUTER,
        keys::WEB_ADMIN_AUDIT_TARGET,
        keys::WEB_ADMIN_AUDIT_OUTCOME,
        keys::WEB_ADMIN_AUDIT_DETAILS,
    ] {
        view = view.head(Head::plain(tr(locale, key, None)));
    }
    for row in rows {
        let time = row
            .time
            .as_ref()
            .map(|time| Piece::time(time.iso().to_owned(), time.text().to_owned()));
        let actor = vec![
            Piece::span("mono", row.actor.clone()),
            Piece::text(" ".to_owned()),
            Piece::span("muted", tr(locale, row.kind, None)),
        ];
        let mut details = Vec::new();
        if !row.params.is_empty() {
            let summary = tr(locale, keys::WEB_ADMIN_AUDIT_PARAMS, None);
            let params = Piece::element("details", String::new())
                .attr("class", "audit-params".to_owned())
                .with(Piece::element("summary", summary))
                .with(Piece::element("pre", row.params.clone()).attr("class", "mono".to_owned()));
            details.push(Line::Piece(params));
        }
        view = view.row(vec![
            Cell::of(time.into_iter().collect()).class("audit-time"),
            Cell::of(actor),
            Cell::code(row.action.clone()),
            Cell::code(row.router.clone()),
            Cell::code(row.target.clone()),
            Cell::code(row.outcome.clone()),
            Cell::stack(details),
        ]);
    }
    view
}

/// The table row of `entry`, in `locale`.
pub(super) fn row(entry: &AuditEntry, locale: Locale) -> EntryRow {
    let params = if entry.params_redacted.is_null() {
        String::new()
    } else {
        entry.params_redacted.to_string()
    };
    EntryRow {
        time: Timestamp::at(entry.ts, locale),
        kind: match entry.actor.kind {
            ActorKind::Web => keys::WEB_ADMIN_AUDIT_KIND_WEB,
            ActorKind::Mcp => keys::WEB_ADMIN_AUDIT_KIND_MCP,
            ActorKind::Cli => keys::WEB_ADMIN_AUDIT_KIND_CLI,
            ActorKind::System | _ => keys::WEB_ADMIN_AUDIT_KIND_SYSTEM,
        },
        actor: entry.actor.id.clone(),
        action: entry.action.clone(),
        router: entry.router.clone().unwrap_or_default(),
        target: entry.target.clone().unwrap_or_default(),
        outcome: entry.outcome.clone(),
        params,
    }
}
