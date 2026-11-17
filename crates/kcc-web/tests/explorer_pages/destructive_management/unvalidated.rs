//! A CLI line outside the catalog, sent through the console's raw escape.

use kcc_i18n::keys;

use super::{CLI, NAME_FIELD, Raw, first_dialog, marker, signed_in, submitted};
use crate::support::outcome::TestResult;

/// E-22: an unvalidated line is a destructive management change: the console asks for the
/// typed router name in the timer's dialog, and a plain confirmation sends nothing.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn an_unvalidated_line_asks_for_the_router_name() -> TestResult {
    let raw: Raw = (
        CLI,
        &[("line", "frobnicate the router"), ("unvalidated", "on")],
        "",
    );
    let (fixture, admin, _) = signed_in("router").await?;
    let dialog = first_dialog(&fixture, &admin, raw).await?;
    assert!(
        dialog.contains(NAME_FIELD)
            && dialog.contains(&marker(keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TEXT)),
        "the destructive management dialog: {dialog}"
    );
    let before = fixture.handle().request_count();
    let unnamed = submitted(&dialog, raw.1, "");
    drop(fixture.post(CLI, &admin, &unnamed).await?);
    assert_eq!(fixture.handle().request_count(), before, "unsent");
    Ok(())
}
