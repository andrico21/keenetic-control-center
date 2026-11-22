//! Changes that reduce safety: the password asked first, a wrong one counted toward the
//! sign-in lockout, and a lockout that leaves the current session signed in.

use axum::http::StatusCode;
use kcc_app::{
    accounts::UsersDocument,
    mcp_settings::{document::McpSettingsDocument, keys::KeyPath},
};
use kcc_i18n::keys;
use kcc_web::admin::mcp_control::McpStatus;
use serde_json::json;

use crate::{
    client::PAGE,
    fixture::Mcp,
    support::{
        base::PASSWORD,
        outcome::TestResult,
        page::{assert_native_post, en},
    },
};

/// Turns `allow_destructive` on.
const DESTRUCTIVE: [(&str, &str); 2] =
    [("field", "allow_destructive"), ("allow_destructive", "on")];

/// The failed sign-ins `users.json` counts for `username`.
fn failures(fixture: &Mcp, username: &str) -> TestResult<u32> {
    let users = fixture.store().read::<UsersDocument>()?.ok_or("no users")?;
    Ok(users
        .users
        .iter()
        .find(|account| account.username == username)
        .ok_or("no account")?
        .failure_count)
}

/// `pairs` with `password`.
fn with_password<'pair>(
    pairs: &[(&'pair str, &'pair str)],
    password: &'pair str,
) -> Vec<(&'pair str, &'pair str)> {
    let mut all = pairs.to_vec();
    all.push(("password", password));
    all
}

/// Regression (todo 27): turning `allow_destructive` on needs the password.
///
/// Without it the password dialog opens and nothing is applied; a wrong password is
/// refused and counted; the right one applies the change through the listeners and
/// audits the changed key.
#[tokio::test]
async fn allow_destructive_needs_the_password() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let (status, dialog) = fixture.save(&admin, &DESTRUCTIVE).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        dialog.contains(&en(keys::WEB_ADMIN_MCP_CONFIRM_TITLE)),
        "{dialog}"
    );
    assert!(
        dialog.contains("name=\"allow_destructive\" value=\"on\""),
        "carried"
    );
    assert_native_post(&dialog)?;
    let (refused, wrong) = fixture
        .save(&admin, &with_password(&DESTRUCTIVE, "not the password"))
        .await?;
    assert_eq!(refused, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        wrong.contains(&en(keys::WEB_ADMIN_MCP_CONFIRM_WRONG)),
        "{wrong}"
    );
    assert!(
        !wrong.contains("not the password"),
        "the typed password is not echoed"
    );
    assert_eq!(failures(&fixture, "admin")?, 1, "the failure counts");
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied yet");
    assert!(
        fixture
            .audited("web.mcp_settings")
            .await?
            .iter()
            .all(|entry| entry.outcome != "success")
    );
    let (applied, done) = fixture
        .save(&admin, &with_password(&DESTRUCTIVE, PASSWORD))
        .await?;
    assert_eq!(applied, StatusCode::OK);
    assert!(done.contains(&en(keys::WEB_ADMIN_MCP_SAVED)), "{done}");
    assert_eq!(
        failures(&fixture, "admin")?,
        0,
        "a right password clears the count"
    );
    let calls = fixture.stub()?.applied();
    assert_eq!(
        calls.first().map(|candidate| candidate.changed().to_vec()),
        Some(vec![KeyPath::AllowDestructive])
    );
    let saved = fixture
        .store()
        .read::<McpSettingsDocument>()?
        .unwrap_or_default();
    assert_eq!(saved.overrides.allow_destructive, Some(true));
    let audited = fixture.audited("web.mcp_settings").await?;
    let entry = audited.last().ok_or("no audit entry")?;
    assert_eq!(entry.outcome, "success");
    assert_eq!(
        entry.params_redacted.get("changed"),
        Some(&json!(["allow_destructive"]))
    );
    assert_eq!(entry.params_redacted.get("restarted"), Some(&json!([])));
    Ok(())
}

/// Regression (todo 27): every kind of safety-reducing change asks for the password
/// before anything is applied, and a change that reduces nothing applies at once.
#[tokio::test]
async fn each_safety_reducing_change_asks_for_the_password() -> TestResult {
    let toml = "[mcp]\nread_only = true\n";
    let fixture = Mcp::build(toml, &[], Some(McpStatus::default())).await?;
    let admin = fixture.login("admin").await?;
    let changes: [&[(&str, &str)]; 9] = [
        &[("field", "read_only")],
        &[("field", "stdio_enabled"), ("stdio_enabled", "on")],
        &[("field", "stdio_role"), ("stdio_role", "admin")],
        &[
            ("field", "toolsets"),
            ("toolsets", "core"),
            ("toolsets", "raw"),
        ],
        &[("field", "auth.main.oauth"), ("auth.main.oauth", "kcc")],
        &[
            ("field", "auth.dedicated.mtls"),
            ("auth.dedicated.mtls", "optional"),
        ],
        &[("field", "dedicated.tls"), ("dedicated.tls", "none")],
        &[
            ("field", "auth.kcc.access_ttl"),
            ("auth.kcc.access_ttl", "1h"),
        ],
        &[
            ("field", "auth.mtls.default_role"),
            ("auth.mtls.default_role", "viewer"),
        ],
    ];
    for pairs in changes {
        let (status, dialog) = fixture.save(&admin, pairs).await?;
        assert_eq!(status, StatusCode::OK, "{pairs:?}");
        assert!(
            dialog.contains(&en(keys::WEB_ADMIN_MCP_CONFIRM_TITLE)),
            "{pairs:?} asks: {dialog}"
        );
    }
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied");
    assert!(fixture.stub()?.restarted().is_empty(), "nothing restarted");
    let (_, safe) = fixture
        .save(
            &admin,
            &[("field", "max_result_bytes"), ("max_result_bytes", "4096")],
        )
        .await?;
    assert!(safe.contains(&en(keys::WEB_ADMIN_MCP_SAVED)), "{safe}");
    assert_eq!(
        fixture.stub()?.applied().len(),
        1,
        "the safe change applied"
    );
    Ok(())
}

/// Regression (todo 27): five wrong passwords lock the account for sign-in and the page
/// says so, while the session that typed them stays signed in.
#[tokio::test]
async fn five_wrong_passwords_lock_sign_in_but_not_the_session() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let wrong = with_password(&DESTRUCTIVE, "not the password");
    for attempt in 1..=4_u32 {
        let (_, answer) = fixture.save(&admin, &wrong).await?;
        assert!(
            answer.contains(&en(keys::WEB_ADMIN_MCP_CONFIRM_WRONG)),
            "attempt {attempt}"
        );
    }
    let (status, locked) = fixture.save(&admin, &wrong).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        locked.contains("data-message-key=\"web-admin-mcp-confirm-locked\""),
        "{locked}"
    );
    let (_, still) = fixture
        .save(&admin, &with_password(&DESTRUCTIVE, PASSWORD))
        .await?;
    assert!(
        still.contains("data-message-key=\"web-admin-mcp-confirm-locked\""),
        "{still}"
    );
    assert!(
        fixture.stub()?.applied().is_empty(),
        "nothing applied while locked"
    );
    let page = fixture.get(PAGE, &admin).await?;
    assert_eq!(page.status(), StatusCode::OK, "the session stays signed in");
    let sign_in = fixture.sign_in("admin", PASSWORD).await?;
    assert_ne!(sign_in.status(), StatusCode::SEE_OTHER, "sign-in is locked");
    Ok(())
}
