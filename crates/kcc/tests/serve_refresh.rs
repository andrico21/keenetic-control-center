//! A running `kcc serve` applies role and key changes without a restart.
//!
//! A permission removed from a custom role in the Web UI binds the same API key's next
//! MCP call, granting it back works too, and a SIGHUP after the role store changed on
//! disk refreshes both the MCP checks and the Web UI. The admin keys page shows the last
//! use of a key, which an MCP call records at most once a minute.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "serve_refresh/support.rs"]
mod support;
#[path = "serve_refresh/web.rs"]
mod web;

use kcc_app::{
    api_keys::ApiKeysDocument,
    permissions::{Permission, RolesDocument},
};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

use crate::{
    support::{Fixture, TestResult, call, client, mcp_session, modified, ops, rpc},
    web::Browser,
};

/// The VPN server password operation: the tool needs `Write`, the operation
/// `ManageUsers`, which only the MCP handler's own check enforces.
fn password_call() -> (&'static str, Value) {
    (
        "kcc_vpn_servers_write",
        json!({"host":"router","op":"password","name":"vpn-guest","secret":"Guest-pass-0451","confirm":true}),
    )
}

/// The role form of `ops` with `manage_users` ticked or not.
fn ops_form(manage_users: bool) -> Vec<(&'static str, &'static str)> {
    let mut form = vec![
        ("name", "ops"),
        ("scope", "*"),
        ("read", "on"),
        ("write", "on"),
    ];
    if manage_users {
        form.push(("manage_users", "on"));
    }
    form
}

/// The error code of a tool answer, if it failed.
fn refusal(answer: &Value) -> Option<&str> {
    answer.get("error").and_then(Value::as_str)
}

/// Saves the `ops` role through the Web UI as `admin`.
async fn edit_ops(http: &Client, base: &str, admin: &Browser, manage_users: bool) -> TestResult {
    let response = admin
        .post(
            http,
            base,
            ("/ui/admin/roles/edit", &ops_form(manage_users)),
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK, "role saved");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_changes_bind_mcp_and_the_web_ui_without_a_restart() -> TestResult {
    let fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let http = client()?;
    let base = fixture.base_url();
    let session = mcp_session(&http, base, fixture.key()).await?;
    let mcp = (base, fixture.key(), session.as_str());
    let granted = call(&http, mcp, password_call()).await?;
    assert_ne!(
        refusal(&granted),
        Some("forbidden"),
        "allowed at start: {granted}"
    );

    let admin = Browser::sign_in(&http, base, "alice").await?;
    edit_ops(&http, base, &admin, false).await?;
    let reduced = call(&http, mcp, password_call()).await?;
    assert_eq!(
        refusal(&reduced),
        Some("forbidden"),
        "the removed permission binds the same key at once: {reduced}"
    );
    edit_ops(&http, base, &admin, true).await?;
    let regranted = call(&http, mcp, password_call()).await?;
    assert_ne!(
        refusal(&regranted),
        Some("forbidden"),
        "granted again: {regranted}"
    );

    let olga = Browser::sign_in(&http, base, "olga").await?;
    let users = olga.get(&http, base, "/ui/admin/users").await?;
    assert_eq!(
        users.status(),
        StatusCode::OK,
        "ManageUsers opens the users page"
    );
    fixture.state()?.update(|roles: &mut RolesDocument| {
        roles.roles = vec![ops(&[Permission::Read, Permission::Write])];
    })?;
    server.hangup()?;
    let reloaded = call(&http, mcp, password_call()).await?;
    assert_eq!(
        refusal(&reloaded),
        Some("forbidden"),
        "SIGHUP reached MCP: {reloaded}"
    );
    let refused = olga.get(&http, base, "/ui/admin/users").await?;
    assert_eq!(
        refused.status(),
        StatusCode::FORBIDDEN,
        "SIGHUP reached the Web UI session"
    );
    Ok(())
}

/// The stored last use of `ops-key`.
fn last_used(fixture: &Fixture) -> TestResult<Option<u64>> {
    Ok(fixture
        .state()?
        .read::<ApiKeysDocument>()?
        .unwrap_or_default()
        .keys
        .into_iter()
        .find(|key| key.name == "ops-key")
        .and_then(|key| key.last_used_at))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_keys_page_shows_a_key_use_recorded_once_a_minute() -> TestResult {
    let fixture = Fixture::new().await?;
    let _server = fixture.serve()?;
    let http = client()?;
    let base = fixture.base_url();
    let admin = Browser::sign_in(&http, base, "alice").await?;
    let before = admin
        .get(&http, base, "/ui/admin/api-keys")
        .await?
        .text()
        .await?;
    assert!(before.contains(">Never<"), "unused key");

    let wrong = rpc(
        &http,
        (base, "not-a-key", None),
        &json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{}}),
    )
    .await?;
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED, "failed auth");
    assert_eq!(last_used(&fixture)?, None, "failed auth records nothing");

    let session = mcp_session(&http, base, fixture.key()).await?;
    let mcp = (base, fixture.key(), session.as_str());
    let listed = call(&http, mcp, ("kcc_routers_list", json!({}))).await?;
    assert_eq!(refusal(&listed), None, "listed: {listed}");
    let recorded = last_used(&fixture)?.ok_or("the use is recorded")?;
    let written = modified(&fixture.keys_file())?;
    let after = admin
        .get(&http, base, "/ui/admin/api-keys")
        .await?
        .text()
        .await?;
    assert!(!after.contains(">Never<"), "no longer Never");
    assert!(after.contains("data-kcc-time"), "a time instead");

    drop(call(&http, mcp, ("kcc_routers_list", json!({}))).await?);
    assert_eq!(last_used(&fixture)?, Some(recorded), "same recorded use");
    assert_eq!(
        modified(&fixture.keys_file())?,
        written,
        "the file is not rewritten"
    );
    Ok(())
}
