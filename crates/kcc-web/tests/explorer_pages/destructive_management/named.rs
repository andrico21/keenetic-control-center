//! A labelled router's destructive console dialog names the router and asks for its id.

use kcc_i18n::keys;

use super::{CLI, NAME_FIELD, Raw, confirm, first_dialog, signed_in};
use crate::support::{
    outcome::TestResult,
    page::{en_with, form, text},
    web::ROUTER,
};

/// A synthetic display name.
const NAME: &str = "Home Office";

/// The explorer endpoint's `DestructiveManagement` request (bridge removal).
const MANAGEMENT: &str = "/ui/r/home/explorer/execute";

/// Todo 11: the Commands family's destructive dialog names a labelled router by its name
/// and asks for its id: the name typed back is refused and nothing is sent, the id runs.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn the_console_dialog_names_the_router_and_asks_for_its_id() -> TestResult {
    let removal: Raw = (CLI, &[("line", "no ip name-server 192.0.2.53")], "");
    let (fixture, admin, _) = signed_in("router").await?;
    fixture.label(ROUTER, NAME).await?;
    drop(fixture.get("/ui/r/home/console/cli", &admin).await?);
    let key = keys::WEB_EXPLORER_CONFIRM_DESTRUCTIVE_TEXT;
    let expected = en_with(key, &[("router", NAME), ("id", ROUTER)]);
    assert_ne!(
        expected,
        en_with(key, &[("router", NAME), ("id", "other")]),
        "the text names the id to type"
    );
    let asked = first_dialog(&fixture, &admin, removal).await?;
    assert!(
        asked.contains(&expected),
        "the dialog names the router and its id: {asked}"
    );
    let before = fixture.handle().request_count();
    let by_name = form(&[
        ("line", "no ip name-server 192.0.2.53"),
        ("confirm", "yes"),
        ("confirm_name", NAME),
    ]);
    let refused = text(fixture.post(CLI, &admin, &by_name).await?).await?;
    assert!(
        refused.contains(NAME_FIELD)
            && refused.contains(&en_with(
                keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
                &[("router", ROUTER)]
            )),
        "the name is not the id: {refused}"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let (_, sent, _) = confirm(&fixture, &admin, removal, &asked).await?;
    assert!(sent > 0, "the id passes the gate");
    Ok(())
}

/// Todo 11: the Management family's destructive dialog shows the help text for confirming
/// by id, not by label: a labelled router's `DestructiveManagement` field help asks for the id.
// NOT cancel-safe: the fixture owns router and HTTP tasks.
#[tokio::test]
async fn the_destructive_management_dialog_asks_for_its_id_in_the_help() -> TestResult {
    let bridge_removal: Raw = (
        MANAGEMENT,
        &[
            ("path", "interface"),
            ("a.name", "Bridge0"),
            ("a.no", "true"),
        ],
        "#explorer-result",
    );
    let (fixture, admin, _) = signed_in("router").await?;
    fixture.label(ROUTER, NAME).await?;
    drop(fixture.get("/ui/r/home/explorer", &admin).await?);
    let help_key = keys::WEB_ADMIN_CONFIRM_HELP;
    let expected_help = en_with(help_key, &[("name", ROUTER)]);
    assert_ne!(
        expected_help,
        en_with(help_key, &[("name", NAME)]),
        "the help asks for the id, not the label"
    );
    let asked = first_dialog(&fixture, &admin, bridge_removal).await?;
    assert!(
        asked.contains(&expected_help),
        "the help text shows the id to type: {asked}"
    );
    let before = fixture.handle().request_count();
    let by_name = form(&[
        ("path", "interface"),
        ("a.name", "Bridge0"),
        ("a.no", "true"),
        ("confirm", "yes"),
        ("confirm_name", NAME),
    ]);
    let refused = text(fixture.post(MANAGEMENT, &admin, &by_name).await?).await?;
    assert!(
        refused.contains(NAME_FIELD)
            && refused.contains(&en_with(
                keys::WEB_EXPLORER_CONFIRM_NAME_ERROR,
                &[("router", ROUTER)]
            )),
        "the label is not the id: {refused}"
    );
    assert_eq!(fixture.handle().request_count(), before, "nothing sent");
    let (_, sent, _) = confirm(&fixture, &admin, bridge_removal, &asked).await?;
    assert!(sent > 0, "the id passes the gate");
    Ok(())
}
