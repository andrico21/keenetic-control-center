//! What the connections tab shows.
//!
//! Grants by account and client, the clients and the count of places taken, the empty states, never a token or a hash, unverified names
//! escaped and isolated, and the golden markup of the tab.

use core::time::Duration;
use std::{fs, path::Path};

use kcc_app::mcp_auth::grants::GrantStore;
use kcc_i18n::keys;
use serde_json::Value;

use crate::{
    fixture::Mcp,
    seed::{RESOURCE, Seed, clock},
    support::{
        outcome::TestResult,
        page::{en, en_with},
    },
};

/// The tab.
pub(crate) const PAGE: &str = "/ui/admin/mcp/connections";

/// The part of `html` from the MCP sub-tabs to the end of the region, with ids and the
/// CSRF token replaced by placeholders.
fn tab_area(html: &str) -> TestResult<String> {
    let start = html
        .find("<nav class=\"tabs mcp-tabs\"")
        .ok_or("the MCP sub-tabs")?;
    let end = html.rfind("</main>").ok_or("the end of the main area")?;
    let area = html.get(start..end).ok_or("the tab area")?;
    let mut normalized = String::with_capacity(area.len());
    let mut run = String::new();
    for character in area.chars() {
        if character.is_ascii_hexdigit() && !character.is_ascii_uppercase() {
            run.push(character);
            continue;
        }
        normalized.push_str(if run.len() == 64 { "<id>" } else { &run });
        run.clear();
        normalized.push(character);
    }
    normalized.push_str(if run.len() == 64 { "<id>" } else { &run });
    Ok(normalized)
}

/// Regression (todo 32): the tab lists live grants by account and the clients.
///
/// Every live grant sits under its account with the client's name, redirect host, times and resource, and every client with the count of
/// places taken; a revoked grant is not listed, and no refresh token hash or password
/// hash of the grants file appears.
#[tokio::test]
async fn grants_are_listed_by_account_and_client() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let claude = seed.client(Some("Claude Code"), "http://127.0.0.1:33418/callback")?;
    let cursor = seed.client(Some("Cursor"), "https://app.example/oauth/cb")?;
    let first = seed.grant(&claude, "alice")?;
    let _second = seed.grant(&cursor, "alice")?;
    let _third = seed.grant(&claude, "bob")?;
    let gone = seed.grant(&cursor, "carol")?;
    let store = GrantStore::new(fixture.store().clone(), clock(), Duration::from_hours(1));
    assert!(store.revoke(gone.id())?, "carol's grant revoked");
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    for shown in [
        "alice",
        "bob",
        "Claude Code",
        "Cursor",
        "127.0.0.1",
        "app.example",
        RESOURCE,
    ] {
        assert!(html.contains(shown), "{shown} shown");
    }
    assert!(!html.contains(">carol<"), "a revoked grant is not listed");
    assert_eq!(
        html.matches("class=\"mcp-grant\"").count(),
        3,
        "three live grants"
    );
    assert_eq!(
        html.matches("class=\"mcp-account\"").count(),
        2,
        "two accounts"
    );
    assert!(
        html.contains(&format!("revoke?grant={}", first.id())),
        "a grant can be revoked"
    );
    assert!(
        html.contains(&en_with(
            keys::WEB_ADMIN_MCP_CONNECTIONS_COUNT,
            &[("count", "2"), ("max", "50")]
        )),
        "places taken"
    );
    let stored = seed.grants_text()?;
    for hash in hashes(&stored) {
        assert!(!html.contains(&hash), "no stored hash on the page");
    }
    assert!(!html.contains("refresh_token") && !html.contains("access_token"));
    Ok(())
}

/// Every 64-digit hex string of the grants file that is not a grant or client id: the
/// refresh token and password hashes.
fn hashes(stored: &str) -> Vec<String> {
    let document: Value = serde_json::from_str(stored).unwrap_or_default();
    let mut found = Vec::new();
    for grant in document
        .pointer("/grants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for pointer in ["/password", "/refresh/current"] {
            found.extend(
                grant
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            );
        }
    }
    assert!(!found.is_empty(), "the grants file holds hashes");
    found
}

/// Regression (todo 32): with no grant and no client the tab says so and points at the
/// registration form, and counts 0 of 50.
#[tokio::test]
async fn the_empty_tab_says_what_to_do_next() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    assert!(html.contains("id=\"mcp-grants-empty\""), "{html}");
    assert!(html.contains(&en(keys::WEB_ADMIN_MCP_CONNECTIONS_GRANTS_EMPTY)));
    assert!(html.contains("id=\"mcp-clients-empty\""));
    assert!(html.contains("id=\"mcp-register-form\""));
    assert!(html.contains(&en_with(
        keys::WEB_ADMIN_MCP_CONNECTIONS_COUNT,
        &[("count", "0"), ("max", "50")]
    )));
    Ok(())
}

/// Regression (todo 32): unverified client names and redirect URIs are made harmless.
///
/// They are escaped, lose their control and format characters (a right-to-left override would make
/// `txt.exe` read `exe.txt`) and sit in a bidirectional isolate; the page has no inline
/// script or style.
#[tokio::test]
async fn hostile_names_and_uris_are_escaped_and_isolated() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let name = "<script>alert(1)</script>\u{202e}txt.exe\u{2066}x";
    let client = seed.client(Some(name), "https://evil.example/<b>cb")?;
    let _grant = seed.grant(&client, "alice")?;
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    assert!(!html.contains("<script>alert"), "the name is escaped");
    assert!(!html.contains("<b>cb"), "the URI is escaped");
    for control in ['\u{202e}', '\u{2066}'] {
        assert!(!html.contains(control), "{control:?} is stripped");
    }
    let isolated =
        "<bdi class=\"mcp-client-name\">&#60;script&#62;alert(1)&#60;/script&#62;txt.exex</bdi>";
    assert_eq!(
        html.matches(isolated).count(),
        2,
        "isolated and stripped in the grant and the client row: {html}"
    );
    assert!(
        html.contains("<bdi class=\"mono mcp-redirect\">https://evil.example/&#60;b&#62;cb</bdi>"),
        "the redirect URI is isolated"
    );
    assert!(!html.contains(" style=") && !html.contains("<script>"));
    Ok(())
}

/// Regression (todo 32): the golden markup of the tab with two accounts and two clients,
/// ids and the CSRF token normalized. The settings tab carries the same sub-tabs.
#[tokio::test]
async fn the_tab_matches_its_golden_markup() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let claude = seed.client(Some("Claude Code"), "http://127.0.0.1:33418/callback")?;
    let cursor = seed.client(None, "com.example.app:/oauth")?;
    let _first = seed.grant(&claude, "alice")?;
    let _second = seed.grant(&cursor, "bob")?;
    let admin = fixture.login("admin").await?;
    let actual = tab_area(&fixture.html(PAGE, &admin).await?)?;
    let golden = include_str!("../fixtures/admin_mcp_connections.html");
    if actual != golden {
        let written = Path::new(env!("CARGO_TARGET_TMPDIR")).join("admin_mcp_connections.html");
        fs::write(&written, &actual)?;
        return Err(format!(
            "the tab differs from its golden markup; actual: {}",
            written.display()
        )
        .into());
    }
    let settings = fixture.html("/ui/admin/mcp", &admin).await?;
    assert!(
        settings.contains("<a class=\"tabs__link\" href=\"/ui/admin/mcp\" aria-current=\"page\">"),
        "the settings tab is current there"
    );
    assert!(settings.contains("href=\"/ui/admin/mcp/connections\""));
    Ok(())
}
