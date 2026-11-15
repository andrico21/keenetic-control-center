//! A destructive line that changes nothing about how kcc reaches the router, and a
//! management line that removes nothing, keep their own dialogs.

use kcc_i18n::keys;

use super::{CLI, NAME_FIELD, Raw, bracket, confirm, first_dialog, marker, signed_in};
use crate::support::outcome::TestResult;

/// Each stake alone keeps its own dialog.
///
/// A destructive line asks for the name in the destructive words and runs without the
/// timer; a management line asks only for the confirm button and runs inside the timer.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn single_stake_lines_keep_their_own_dialogs() -> TestResult {
    let removal = "no ip name-server 192.0.2.53";
    let destructive: Raw = (CLI, &[("line", "no ip name-server 192.0.2.53")], "");
    let management: Raw = (CLI, &[("line", "system mode extender")], "");
    for mode in ["router", "extender"] {
        let (fixture, admin, _) = signed_in(mode).await?;
        let (arm, disarm) = bracket(mode);
        let named = first_dialog(&fixture, &admin, destructive).await?;
        assert!(
            named.contains(&marker(keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TEXT))
                && named.contains(NAME_FIELD)
                && !named.contains(&marker(keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TEXT))
                && !named.contains("confirm-name-help"),
            "the destructive dialog: {named}"
        );
        let (_, _, removal_lines) = confirm(&fixture, &admin, destructive, &named).await?;
        assert!(
            removal_lines.iter().any(|line| line == removal)
                && !removal_lines.iter().any(|line| line == arm),
            "sent without the timer: {removal_lines:?}"
        );
        let timed = first_dialog(&fixture, &admin, management).await?;
        assert!(
            timed.contains(&marker(keys::WEB_EXPLORER_CONFIRM_MANAGEMENT_TEXT))
                && !timed.contains(NAME_FIELD),
            "the management dialog: {timed}"
        );
        let (_, _, mode_lines) = confirm(&fixture, &admin, management, &timed).await?;
        assert_eq!(
            (
                mode_lines.first().map(String::as_str),
                mode_lines.last().map(String::as_str)
            ),
            (Some(arm), Some(disarm)),
            "inside the timer: {mode_lines:?}"
        );
    }
    Ok(())
}
