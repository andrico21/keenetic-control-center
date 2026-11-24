//! Each change touches exactly what it names; client names lose their format characters.
//!
//! Revoking one grant keeps the account's other grants, revoking an account keeps an
//! account whose name merely starts or ends alike, the dialogs strip bidirectional
//! controls from client names, and a grant past its refresh expiry is not listed.

use axum::http::StatusCode;
use kcc_i18n::keys;
use serde_json::json;

use crate::{
    changes::asks,
    fixture::Mcp,
    listing::PAGE,
    seed::Seed,
    support::{outcome::TestResult, page::text},
};

/// Regression (todo 32): revoking one grant keeps every other grant of its account.
///
/// Alice holds two grants of one client and one of another; revoking one of them leaves
/// the other two live, and the audit entry names that grant alone.
#[tokio::test]
async fn revoking_one_grant_keeps_the_accounts_other_grants() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let claude = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let cursor = seed.client(Some("Cursor"), "https://app.example/cb")?;
    let target = seed.grant(&claude, "alice")?;
    let same_client = seed.grant(&claude, "alice")?;
    let other_client = seed.grant(&cursor, "alice")?;
    let admin = fixture.login("admin").await?;
    let path = format!("/ui/admin/mcp/connections/revoke?grant={}", target.id());
    let done = fixture.post(&path, &admin, &[("confirm", "yes")]).await?;
    assert_eq!(done.status(), StatusCode::OK);
    assert!(!seed.live(target.id())?, "revoked");
    assert!(
        seed.live(same_client.id())?,
        "the account's grant of the same client stays"
    );
    assert!(
        seed.live(other_client.id())?,
        "the account's grant of another client stays"
    );
    let entries = fixture.audited("web.mcp_grant_revoke").await?;
    let [entry] = entries.as_slice() else {
        return Err(format!("one entry, got {}", entries.len()).into());
    };
    assert_eq!(
        entry.params_redacted.pointer("/grants"),
        Some(&json!([target.id()]))
    );
    Ok(())
}

/// Regression (todo 32): revoking an account spares a name that starts alike.
///
/// It revokes that account only, never one whose name starts with it or that it starts
/// with (`olga` and `olgab`).
#[tokio::test]
async fn revoking_an_account_spares_a_name_that_starts_alike() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    seed.holder("olga")?;
    seed.holder("olgab")?;
    let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let olga = seed.grant(&client, "olga")?;
    let olgab = seed.grant(&client, "olgab")?;
    let admin = fixture.login("admin").await?;
    let revoke_all = |name: &'static str| {
        (
            format!("/ui/admin/mcp/connections/revoke-account?account={name}"),
            [("confirm", "yes"), ("object", name), ("confirm_name", name)],
        )
    };
    let (path, typed) = revoke_all("olgab");
    let done = fixture.post(&path, &admin, &typed).await?;
    assert_eq!(done.status(), StatusCode::OK);
    assert!(!seed.live(olgab.id())?, "olgab's grant revoked");
    assert!(seed.live(olga.id())?, "olga's grant stays");
    let again = seed.grant(&client, "olgab")?;
    let (shorter, shorter_typed) = revoke_all("olga");
    let shorter_done = fixture.post(&shorter, &admin, &shorter_typed).await?;
    assert_eq!(shorter_done.status(), StatusCode::OK);
    assert!(!seed.live(olga.id())?, "olga's grant revoked");
    assert!(seed.live(again.id())?, "olgab's grant stays");
    Ok(())
}

/// Regression (todo 32): the dialogs strip format characters from client names.
///
/// The revoke and delete dialogs name the client without its bidirectional and
/// zero-width format characters.
#[tokio::test]
async fn the_dialogs_strip_format_characters_from_client_names() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let client = seed.client(
        Some("Tool\u{202e}txt.exe\u{200b}x"),
        "http://127.0.0.1:9/cb",
    )?;
    let grant = seed.grant(&client, "alice")?;
    let admin = fixture.login("admin").await?;
    for (path, key) in [
        (
            format!("/ui/admin/mcp/connections/revoke?grant={}", grant.id()),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_TEXT,
        ),
        (
            format!("/ui/admin/mcp/clients/delete?client={}", client.id()),
            keys::WEB_ADMIN_MCP_CONNECTIONS_DELETE_TEXT,
        ),
    ] {
        let html = text(fixture.post(&path, &admin, &[]).await?).await?;
        assert!(html.contains("Tooltxt.exex"), "the name is shown: {html}");
        for format in ['\u{202e}', '\u{200b}'] {
            assert!(!html.contains(format), "{path}: {format:?} is stripped");
        }
        asks(fixture.post(&path, &admin, &[]).await?, key).await?;
    }
    Ok(())
}

/// Regression (todo 32): an expired grant is not listed.
///
/// A grant whose refresh token expired is not listed, though it was never revoked; the
/// live one beside it is.
#[tokio::test]
async fn an_expired_grant_is_not_listed() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let live = seed.grant(&client, "alice")?;
    let expired = seed.expired_grant(&client, "bob")?;
    let stored = seed.grants()?;
    let kept = stored
        .get(expired.id())
        .ok_or("the expired grant is stored")?;
    assert!(!kept.is_revoked(), "expired, not revoked");
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    assert!(
        html.contains(&format!("revoke?grant={}", live.id())),
        "{html}"
    );
    assert!(
        !html.contains(expired.id()),
        "the expired grant is not listed: {html}"
    );
    assert_eq!(html.matches("class=\"mcp-grant\"").count(), 1);
    Ok(())
}
