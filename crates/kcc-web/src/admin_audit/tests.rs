//! Paging of the audit page.

#![expect(
    clippy::missing_panics_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]

use kcc_app::permissions::Permission;

use super::*;
use crate::table::pager::PAGE_ROWS;

fn entry(seq: u64) -> Option<AuditEntry> {
    serde_json::from_value(json!({
        "ts": seq,
        "seq": seq,
        "actor": {"kind": "web", "id": "tester"},
        "router": null,
        "action": format!("a{seq}"),
        "target": null,
        "params_redacted": null,
        "outcome": "success",
        "request_id": "web-1",
        "prev_hash": "0",
        "hash": "0",
    }))
    .ok()
}

/// W1-08: a long log becomes the rows of one page, newest first, and the next page
/// continues where it ends.
#[test]
fn only_the_requested_page_becomes_rows() {
    let total = PAGE_ROWS.saturating_mul(3).saturating_add(10);
    let entries = (1..=u64::try_from(total).unwrap_or_default())
        .filter_map(entry)
        .collect();
    let log = Log::new(Chain::Intact(total), entries);
    let role = Role::new(
        "all".to_owned(),
        [Permission::ViewAudit],
        vec!["*".to_owned()],
    );
    let filter = Filter::parse(&AuditQuery::default());
    let (first, pager) = page_rows(&log, &filter, &role, Locale::En, 1);
    assert_eq!(first.len(), PAGE_ROWS, "one page of rows");
    assert!(pager.multiple(), "more pages follow");
    assert_eq!(
        first.first().map(|row| row.action.as_str()),
        Some(format!("a{total}").as_str())
    );
    let (last, _) = page_rows(&log, &filter, &role, Locale::En, 4);
    assert_eq!(last.len(), 10, "the rest on the last page");
}
