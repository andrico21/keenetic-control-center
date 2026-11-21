//! A running `kcc serve` applies what other processes change in `api_keys.json` and
//! `users.json` (a CLI key revocation, account disable or password reset, a role changed
//! on disk) within its 2-second poll. A rewrite that changes no key, role, disabled flag
//! or password does not reload, and an unreadable file keeps the last good state.
#![cfg(unix)]
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "serve_state_watch/support.rs"]
mod support;
#[path = "serve_refresh/web.rs"]
mod web;

use core::time::Duration;
use std::{fs, path::Path};

use kcc_app::{
    accounts::UsersDocument,
    api_keys::{ApiKeysDocument, record_api_key_use},
};
use reqwest::{StatusCode, header};
use serde_json::Value;

use crate::{
    support::{
        Fixture, KEY_NAME, PASSWORD, PROPAGATION, RELOAD, TestResult, WATCH, about, warning,
    },
    web::Browser,
};

/// The API key store.
const KEYS: &str = "api_keys.json";

/// The account store.
const USERS: &str = "users.json";

/// Whether `browser`'s session still opens a page (`200`) rather than being sent to the
/// login page (`303`).
async fn signed_in(fixture: &Fixture, browser: &Browser) -> TestResult<bool> {
    let status = browser
        .get(fixture.http(), fixture.base(), "/ui/account")
        .await?
        .status();
    match status {
        StatusCode::OK => Ok(true),
        StatusCode::SEE_OTHER => Ok(false),
        other => Err(format!("unexpected status {other}").into()),
    }
}

/// The CSRF token of a rendered page.
fn csrf(html: &str) -> TestResult<String> {
    html.split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
        .ok_or_else(|| "no CSRF token".into())
}

/// A password other than [`PASSWORD`], built at run time.
fn replacement() -> String {
    ["replaced", "passphrase", "0451"].join("-")
}

/// Moves `path`'s modification time one second forward without changing its content.
fn touch(path: &Path) -> TestResult {
    let file = fs::File::options().write(true).open(path)?;
    let modified = file
        .metadata()?
        .modified()?
        .checked_add(Duration::from_secs(1))
        .ok_or("time overflow")?;
    file.set_modified(modified)?;
    Ok(())
}

/// F-01: a key revoked with the CLI is refused by the running server within 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_revoked_with_the_cli_is_refused() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve()?;
    assert_eq!(fixture.mcp_status().await?, StatusCode::OK, "the key works");

    fixture.cli(&["apikey", "revoke", KEY_NAME])?;
    let reloaded = server.wait_event(PROPAGATION, |event| about(event, RELOAD, KEYS))?;

    assert_eq!(
        fixture.mcp_status().await?,
        StatusCode::UNAUTHORIZED,
        "the revoked key still authenticates"
    );
    assert!(reloaded, "no key reload was logged");
    Ok(())
}

/// Todo 25: `kcc serve` starts one state watcher, outside the MCP server's start-up;
/// the key change it applies reaches the server registered after it started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_state_watch_starts_once() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve()?;

    fixture.cli(&["apikey", "revoke", KEY_NAME])?;
    let reloaded = server.wait_event(PROPAGATION, |event| about(event, RELOAD, KEYS))?;

    assert!(reloaded, "no key reload was logged");
    assert_eq!(
        fixture.mcp_status().await?,
        StatusCode::UNAUTHORIZED,
        "the revoked key still authenticates"
    );
    let starts = server.count(|event| {
        event.get("target").and_then(Value::as_str) == Some(WATCH)
            && event.pointer("/fields/interval_ms").is_some()
    });
    assert_eq!(starts, 1, "state watchers started");
    Ok(())
}

/// F-01, SEC1-05, W1-01: an account disabled with the CLI loses its live Web session
/// within 5 s; other accounts keep theirs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_account_disabled_with_the_cli_loses_its_session() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve()?;
    let bob = Browser::sign_in(fixture.http(), fixture.base(), "bob").await?;
    let alice = Browser::sign_in(fixture.http(), fixture.base(), "alice").await?;
    assert!(signed_in(&fixture, &bob).await?, "bob is signed in");

    fixture.cli(&["user", "disable", "bob"])?;
    let reloaded = server.wait_event(PROPAGATION, |event| about(event, RELOAD, USERS))?;

    assert!(
        !signed_in(&fixture, &bob).await?,
        "the disabled account's session still works"
    );
    assert!(
        signed_in(&fixture, &alice).await?,
        "alice keeps her session"
    );
    assert!(reloaded, "no account reload was logged");
    Ok(())
}

/// SEC1-05, W1-01: a password reset with the CLI ends every session of the account
/// within 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_password_reset_with_the_cli_ends_the_sessions() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve()?;
    let first = Browser::sign_in(fixture.http(), fixture.base(), "bob").await?;
    let second = Browser::sign_in(fixture.http(), fixture.base(), "bob").await?;
    let password = fixture.secret_file("bob.password", &replacement())?;

    fixture.cli(&["--password-file", &password, "user", "passwd", "bob"])?;
    let reloaded = server.wait_event(PROPAGATION, |event| about(event, RELOAD, USERS))?;

    assert!(
        !signed_in(&fixture, &first).await?,
        "a session from before the reset still works"
    );
    assert!(
        !signed_in(&fixture, &second).await?,
        "the other session from before the reset still works"
    );
    assert!(reloaded, "no account reload was logged");
    Ok(())
}

/// SEC1-05: a role reduced in `users.json` outside the server (the CLI has no role
/// command; this is an edited or restored file) ends the account's session within 5 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_role_reduced_on_disk_ends_the_session() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve()?;
    let bob = Browser::sign_in(fixture.http(), fixture.base(), "bob").await?;

    fixture.state()?.update(|document: &mut UsersDocument| {
        for account in document
            .users
            .iter_mut()
            .filter(|user| user.username == "bob")
        {
            "viewer".clone_into(&mut account.role);
        }
    })?;
    let reloaded = server.wait_event(PROPAGATION, |event| about(event, RELOAD, USERS))?;

    assert!(
        !signed_in(&fixture, &bob).await?,
        "the session keeps working after the role was reduced"
    );
    assert!(reloaded, "no account reload was logged");
    Ok(())
}

/// W1-01, SEC1-12: an own password change keeps its session under a new id.
///
/// The session moves to a new id and CSRF token and is still signed in after the server
/// reloads the changed account. The old id and the account's other sessions end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_own_password_change_keeps_its_session() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve()?;
    let kept = Browser::sign_in(fixture.http(), fixture.base(), "bob").await?;
    let other = Browser::sign_in(fixture.http(), fixture.base(), "bob").await?;
    let before = csrf(
        &kept
            .get(fixture.http(), fixture.base(), "/ui/account")
            .await?
            .text()
            .await?,
    )?;
    let new_password = replacement();

    let changed = kept
        .post(
            fixture.http(),
            fixture.base(),
            (
                "/ui/account/password",
                &[
                    ("current_password", PASSWORD),
                    ("new_password", new_password.as_str()),
                ],
            ),
        )
        .await?;
    assert_eq!(
        changed.status(),
        StatusCode::SEE_OTHER,
        "the change is accepted"
    );
    let rotated = changed
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .ok_or("no new session cookie")?
        .to_owned();
    let reloaded = server.wait_event(PROPAGATION, |event| about(event, RELOAD, USERS))?;

    assert!(reloaded, "no account reload was logged");
    let account = fixture
        .http()
        .get(format!("{}/ui/account", fixture.base()))
        .header(header::COOKIE, &rotated)
        .send()
        .await?;
    assert_eq!(
        account.status(),
        StatusCode::OK,
        "the session that changed the password was ended"
    );
    assert_ne!(
        csrf(&account.text().await?)?,
        before,
        "the CSRF token stayed"
    );
    assert!(
        !signed_in(&fixture, &kept).await?,
        "the old session id still works"
    );
    assert!(
        !signed_in(&fixture, &other).await?,
        "the other session survived"
    );
    Ok(())
}

/// F-01: an `mtime`-only touch of either file and a key's `last_used` record rewrite
/// the files without changing a key, role, disabled flag or password, so nothing reloads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrites_without_a_change_do_not_reload() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve()?;

    touch(&fixture.file(KEYS))?;
    let touched = server.wait_event(PROPAGATION, |event| about(event, WATCH, KEYS))?;
    let _known: bool = record_api_key_use(&fixture.state()?, KEY_NAME, 4242)?;
    let used = server.wait_event(PROPAGATION, |event| about(event, WATCH, KEYS))?;
    touch(&fixture.file(USERS))?;
    let users = server.wait_event(PROPAGATION, |event| about(event, WATCH, USERS))?;

    assert!(
        touched && used && users,
        "the watcher did not report each rewrite (touch {touched}, last_used {used}, users {users})"
    );
    assert!(
        !server.saw(|event| event.get("target").and_then(Value::as_str) == Some(RELOAD)),
        "a rewrite without a change reloaded"
    );
    assert_eq!(fixture.mcp_status().await?, StatusCode::OK, "the key works");
    Ok(())
}

/// F-01: an unparsable `api_keys.json` or `users.json` logs a warning and keeps the last
/// good state; the next valid file is applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_file_keeps_the_last_good_state() -> TestResult {
    let fixture = Fixture::new()?;
    let mut server = fixture.serve()?;
    let bob = Browser::sign_in(fixture.http(), fixture.base(), "bob").await?;

    fs::write(fixture.file(KEYS), b"{ not json")?;
    let keys_warned = server.wait_event(PROPAGATION, |event| {
        about(event, WATCH, KEYS) && warning(event)
    })?;
    fs::write(fixture.file(USERS), b"{ not json")?;
    let users_warned = server.wait_event(PROPAGATION, |event| {
        about(event, WATCH, USERS) && warning(event)
    })?;

    assert!(
        keys_warned && users_warned,
        "no warning (keys {keys_warned}, users {users_warned})"
    );
    assert_eq!(
        fixture.mcp_status().await?,
        StatusCode::OK,
        "keys were dropped"
    );
    assert!(signed_in(&fixture, &bob).await?, "sessions were dropped");

    fixture.state()?.write(&ApiKeysDocument::default())?;
    let reloaded = server.wait_event(PROPAGATION, |event| about(event, RELOAD, KEYS))?;
    assert!(reloaded, "the repaired file was not applied");
    assert_eq!(
        fixture.mcp_status().await?,
        StatusCode::UNAUTHORIZED,
        "the repaired file without the key was not applied"
    );
    Ok(())
}
