//! Revoking one grant, every grant of an account, and deleting a client with its grants:
//! each asks first, acts only on its confirmation, touches nothing else, and is audited
//! with ids only.

use axum::{http::StatusCode, response::Response};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::{Value, json};

use crate::{
    fixture::Mcp,
    seed::Seed,
    support::{
        outcome::TestResult,
        page::{en, header_text, text},
    },
};

/// Asserts `response` is the confirmation dialog marked with `key`.
pub(crate) async fn asks(response: Response, key: MessageKey) -> TestResult {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_text(&response, "hx-retarget").as_deref(),
        Some("#dialog-content"),
        "shown in the dialog"
    );
    let html = text(response).await?;
    assert!(
        html.contains(&format!("data-message-key=\"{}\"", key.id())),
        "{html}"
    );
    Ok(())
}

/// The audit params of the single `action` entry.
async fn audited(fixture: &Mcp, action: &str) -> TestResult<(Option<String>, Value, String)> {
    let entries = fixture.audited(action).await?;
    let [entry] = entries.as_slice() else {
        return Err(format!("one {action} entry, got {}", entries.len()).into());
    };
    Ok((
        entry.target.clone(),
        entry.params_redacted.clone(),
        entry.outcome.clone(),
    ))
}

/// Regression (todo 32): Revoke asks first, then revokes exactly that grant.
///
/// Confirmed, it revokes exactly that grant,
/// answers with the region out of band and closes the dialog, and the audit entry names
/// the account, client and grant only. An unknown grant is 404.
#[tokio::test]
async fn revoking_one_grant_asks_then_revokes_only_it() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let target = seed.grant(&client, "alice")?;
    let other = seed.grant(&client, "bob")?;
    let admin = fixture.login("admin").await?;
    let path = format!("/ui/admin/mcp/connections/revoke?grant={}", target.id());
    let first = fixture.post(&path, &admin, &[]).await?;
    asks(first, keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_TEXT).await?;
    assert!(
        seed.live(target.id())?,
        "nothing revoked before the confirmation"
    );
    let done = fixture.post(&path, &admin, &[("confirm", "yes")]).await?;
    assert_eq!(done.status(), StatusCode::OK);
    assert_eq!(header_text(&done, "hx-reswap").as_deref(), Some("none"));
    let html = text(done).await?;
    assert!(html.contains("id=\"mcp-connections-region\" hx-swap-oob=\"true\""));
    assert!(html.contains(&en(keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKED)));
    assert!(!seed.live(target.id())?, "revoked");
    assert!(seed.live(other.id())?, "the other grant stays");
    let (audit_target, params, outcome) = audited(&fixture, "web.mcp_grant_revoke").await?;
    assert_eq!(audit_target.as_deref(), Some(target.id()));
    assert_eq!(
        params,
        json!({"account": "alice", "client": client.id(), "grants": [target.id()]})
    );
    assert_eq!(outcome, "success");
    let again = fixture.post(&path, &admin, &[("confirm", "yes")]).await?;
    assert_eq!(again.status(), StatusCode::NOT_FOUND, "already revoked");
    let unknown = format!("/ui/admin/mcp/connections/revoke?grant={}", "a".repeat(64));
    let missing = fixture
        .post(&unknown, &admin, &[("confirm", "yes")])
        .await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// Regression (todo 32): Revoke all asks for the account name; a wrong name revokes
/// nothing; the right one revokes every grant of that account and none of another's.
#[tokio::test]
async fn revoking_an_account_revokes_its_grants_only() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let claude = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let cursor = seed.client(Some("Cursor"), "https://app.example/cb")?;
    let alice = [seed.grant(&claude, "alice")?, seed.grant(&cursor, "alice")?];
    let bob = seed.grant(&claude, "bob")?;
    let carol = seed.grant(&cursor, "carol")?;
    let admin = fixture.login("admin").await?;
    let path = "/ui/admin/mcp/connections/revoke-account?account=alice";
    let first = fixture.post(path, &admin, &[]).await?;
    asks(first, keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_ALL_TEXT).await?;
    let wrong = [
        ("confirm", "yes"),
        ("object", "alice"),
        ("confirm_name", "bob"),
    ];
    let refused = fixture.post(path, &admin, &wrong).await?;
    asks(refused, keys::WEB_ADMIN_MCP_CONNECTIONS_REVOKE_ALL_TEXT).await?;
    assert!(
        seed.live(alice[0].id())? && seed.live(alice[1].id())?,
        "kept"
    );
    let typed = [
        ("confirm", "yes"),
        ("object", "alice"),
        ("confirm_name", "alice"),
    ];
    let done = fixture.post(path, &admin, &typed).await?;
    assert_eq!(done.status(), StatusCode::OK);
    for grant in &alice {
        assert!(!seed.live(grant.id())?, "alice's grant revoked");
    }
    assert!(
        seed.live(bob.id())? && seed.live(carol.id())?,
        "others kept"
    );
    let (audit_target, params, _) = audited(&fixture, "web.mcp_grant_revoke").await?;
    assert_eq!(audit_target.as_deref(), Some("alice"));
    assert_eq!(params.pointer("/account"), Some(&json!("alice")));
    let mut ids = params
        .pointer("/grants")
        .and_then(Value::as_array)
        .ok_or("grant ids")?
        .clone();
    ids.sort_by_key(ToString::to_string);
    let mut expected = vec![json!(alice[0].id()), json!(alice[1].id())];
    expected.sort_by_key(ToString::to_string);
    assert_eq!(ids, expected);
    let none = "/ui/admin/mcp/connections/revoke-account?account=alice";
    let nothing = [
        ("confirm", "yes"),
        ("object", "alice"),
        ("confirm_name", "alice"),
    ];
    let empty = fixture.post(none, &admin, &nothing).await?;
    assert_eq!(
        empty.status(),
        StatusCode::NOT_FOUND,
        "nothing left to revoke"
    );
    Ok(())
}

/// Regression (todo 32): Delete asks first, then removes the client with its grants.
///
/// Confirmed, it removes the client and revokes
/// every grant it holds in the same change, keeps the other client's grants, and the
/// audit entry names the client and the revoked grants only.
#[tokio::test]
async fn deleting_a_client_revokes_its_grants() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let claude = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let cursor = seed.client(Some("Cursor"), "https://app.example/cb")?;
    let gone = [seed.grant(&claude, "alice")?, seed.grant(&claude, "bob")?];
    let kept = seed.grant(&cursor, "alice")?;
    let admin = fixture.login("admin").await?;
    let path = format!("/ui/admin/mcp/clients/delete?client={}", claude.id());
    let first = fixture.post(&path, &admin, &[]).await?;
    asks(first, keys::WEB_ADMIN_MCP_CONNECTIONS_DELETE_TEXT).await?;
    assert!(
        seed.clients()?.client(claude.id()).is_some(),
        "kept until confirmed"
    );
    let done = fixture.post(&path, &admin, &[("confirm", "yes")]).await?;
    assert_eq!(done.status(), StatusCode::OK);
    assert!(seed.clients()?.client(claude.id()).is_none(), "deleted");
    assert!(
        seed.clients()?.client(cursor.id()).is_some(),
        "the other client stays"
    );
    for grant in &gone {
        assert!(!seed.live(grant.id())?, "its grants are revoked");
    }
    assert!(seed.live(kept.id())?, "the other client's grant stays");
    let (audit_target, params, outcome) = audited(&fixture, "web.mcp_client_delete").await?;
    assert_eq!(audit_target.as_deref(), Some(claude.id()));
    assert_eq!(params.pointer("/client"), Some(&json!(claude.id())));
    assert_eq!(
        params
            .pointer("/grants")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(outcome, "success");
    let again = fixture.post(&path, &admin, &[("confirm", "yes")]).await?;
    assert_eq!(again.status(), StatusCode::NOT_FOUND);
    Ok(())
}

/// Regression (todo 32): no audit entry of the tab carries a token, a hash, a redirect
/// URI or a client name: ids, the account and outcomes only.
#[tokio::test]
async fn audit_entries_carry_ids_only() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let client = seed.client(Some("Secret Name Client"), "https://hidden.example/cb")?;
    let grant = seed.grant(&client, "alice")?;
    let stored = seed.grants_text()?;
    let admin = fixture.login("admin").await?;
    let revoke = format!("/ui/admin/mcp/connections/revoke?grant={}", grant.id());
    drop(fixture.post(&revoke, &admin, &[("confirm", "yes")]).await?);
    let delete = format!("/ui/admin/mcp/clients/delete?client={}", client.id());
    drop(fixture.post(&delete, &admin, &[("confirm", "yes")]).await?);
    let pairs = [
        ("name", "Pre Named"),
        ("redirect_uris", "https://pre.example/cb"),
    ];
    drop(
        fixture
            .post("/ui/admin/mcp/clients", &admin, &pairs)
            .await?,
    );
    let audit = fixture.audit_text().await?;
    for secret in [
        "Secret Name Client",
        "hidden.example",
        "Pre Named",
        "pre.example",
        "password",
        "refresh",
    ] {
        assert!(!audit.contains(secret), "{secret} in {audit}");
    }
    let document: Value = serde_json::from_str(&stored)?;
    for pointer in ["/grants/0/password", "/grants/0/refresh/current"] {
        let hash = document
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or(pointer)?;
        assert!(!audit.contains(hash), "{pointer} not audited");
    }
    for action in [
        "web.mcp_grant_revoke",
        "web.mcp_client_delete",
        "web.mcp_client_register",
    ] {
        let entries = fixture.audited(action).await?;
        assert_eq!(entries.len(), 1, "{action}");
        for entry in entries {
            let keys = entry
                .params_redacted
                .as_object()
                .map_or_default(|params| params.keys().cloned().collect::<Vec<_>>());
            assert!(
                keys.iter()
                    .all(|key| ["account", "client", "grants"].contains(&key.as_str())),
                "{action}: {keys:?}"
            );
        }
    }
    Ok(())
}
