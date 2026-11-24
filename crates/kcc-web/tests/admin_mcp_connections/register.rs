//! Pre-registering a client under the registration rules.
//!
//! The rules of `/oauth/register` for every
//! refused redirect URI class, name and count, the 50-client limit that counts
//! pre-registered clients, and no field beyond the name and the URIs.

use axum::http::StatusCode;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use serde_json::json;

use crate::{
    fixture::Mcp,
    seed::Seed,
    support::{
        outcome::TestResult,
        page::{en, en_with, text},
    },
};

/// The form's endpoint.
const REGISTER: &str = "/ui/admin/mcp/clients";

/// One refused redirect URI per refusal class, with the reason the page gives.
fn refused_uris() -> Vec<(String, MessageKey)> {
    vec![
        (
            format!("https://long.example/{}", "x".repeat(600)),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_LONG,
        ),
        (
            "https://space.example/a b".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_CHARACTERS,
        ),
        (
            "https://*.example/cb".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_WILDCARD,
        ),
        (
            "https://frag.example/cb#x".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_FRAGMENT,
        ),
        (
            "not a uri".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_CHARACTERS,
        ),
        (
            "relative/path".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_UNPARSABLE,
        ),
        (
            "https://user:pw@info.example/cb".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_USERINFO,
        ),
        (
            "http://plain.example/cb".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_HTTP,
        ),
        (
            "javascript:alert(1)".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_SCHEME,
        ),
        (
            "myapp:/cb".to_owned(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_SCHEME,
        ),
    ]
}

/// Regression (todo 32): pre-registration refuses what `/oauth/register` refuses.
///
/// Every refused redirect URI class, a bad name and a wrong count answer 422 with the localized reason on the form, store nothing, and are audited as
/// refused; a valid loopback, https or app-scheme client is stored as pre-registered and
/// audited with its id only.
#[tokio::test]
async fn pre_registration_follows_the_registration_rules() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let admin = fixture.login("admin").await?;
    for (uri, reason) in refused_uris() {
        let lines = format!("https://fine.example/cb\n{uri}");
        let answer = fixture
            .post(
                REGISTER,
                &admin,
                &[("name", "Tool"), ("redirect_uris", &lines)],
            )
            .await?;
        assert_eq!(answer.status(), StatusCode::UNPROCESSABLE_ENTITY, "{uri}");
        let html = text(answer).await?;
        let said = en_with(
            keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_REDIRECT,
            &[("item", "2"), ("what", &tr(Locale::En, reason, None))],
        );
        assert!(html.contains(&said), "{uri}: {said} in {html}");
        assert!(html.contains("id=\"mcp-register-uris-error\""));
    }
    let too_many = (1..=6_u32)
        .map(|n| format!("https://n{n}.example/cb"))
        .collect::<Vec<_>>()
        .join("\n");
    for (name, uris, key) in [
        ("Tool", "", keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_COUNT),
        (
            "Tool",
            too_many.as_str(),
            keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_COUNT,
        ),
        (
            &"n".repeat(65),
            "https://a.example/cb",
            keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_NAME,
        ),
        (
            "bad\u{7}name",
            "https://a.example/cb",
            keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_NAME,
        ),
    ] {
        let answer = fixture
            .post(REGISTER, &admin, &[("name", name), ("redirect_uris", uris)])
            .await?;
        assert_eq!(
            answer.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name} {uris}"
        );
        assert!(text(answer).await?.contains(&en(key)), "{name} {uris}");
    }
    assert!(seed.clients()?.clients().is_empty(), "nothing stored");
    let refusals = fixture.audited("web.mcp_client_register").await?;
    assert_eq!(refusals.len(), 14, "every refusal audited");
    assert!(
        refusals
            .iter()
            .all(|entry| entry.outcome == "validation_failed")
    );
    let valid = "http://127.0.0.1:7777/callback\r\nhttps://app.example/cb\ncom.example.app:/oauth";
    let answer = fixture
        .post(
            REGISTER,
            &admin,
            &[("name", "Desktop Tool"), ("redirect_uris", valid)],
        )
        .await?;
    assert_eq!(answer.status(), StatusCode::OK);
    let html = text(answer).await?;
    assert!(html.contains(&en(keys::WEB_ADMIN_MCP_CONNECTIONS_REGISTERED)));
    assert!(html.contains("Desktop Tool"), "listed");
    let clients = seed.clients()?;
    let [client] = clients.clients() else {
        return Err("one client".into());
    };
    assert!(client.is_pre_registered(), "never purged");
    assert_eq!(client.name(), Some("Desktop Tool"));
    assert_eq!(
        client.redirect_uris(),
        [
            "http://127.0.0.1:7777/callback",
            "https://app.example/cb",
            "com.example.app:/oauth"
        ]
    );
    let entries = fixture.audited("web.mcp_client_register").await?;
    let done = entries
        .iter()
        .find(|entry| entry.outcome == "success")
        .ok_or("audited")?;
    assert_eq!(done.target.as_deref(), Some(client.id()));
    assert_eq!(done.params_redacted, json!({ "client": client.id() }));
    Ok(())
}

/// Regression (todo 32): the form takes the name and the URIs only: a path or any other
/// field is refused and nothing is stored.
#[tokio::test]
async fn no_field_beyond_name_and_uris_is_accepted() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let admin = fixture.login("admin").await?;
    for extra in [
        ("path", "/etc/passwd"),
        ("pre_registered", "false"),
        ("id", "a"),
    ] {
        let pairs = [
            ("name", "Tool"),
            ("redirect_uris", "https://a.example/cb"),
            extra,
        ];
        let answer = fixture.post(REGISTER, &admin, &pairs).await?;
        assert_eq!(
            answer.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{extra:?}"
        );
    }
    assert!(seed.clients()?.clients().is_empty(), "nothing stored");
    Ok(())
}

/// Regression (todo 32): 49 clients leave one place, which pre-registration takes; the
/// 51st is refused as full with the count shown, though it is an administrator's.
#[tokio::test]
async fn the_limit_of_fifty_counts_pre_registered_clients() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    for n in 1..=49 {
        drop(seed.client(None, &format!("http://127.0.0.1:{}/cb", 20_000_u32 + n))?);
    }
    let admin = fixture.login("admin").await?;
    let pairs = [
        ("name", "Last"),
        ("redirect_uris", "https://last.example/cb"),
    ];
    let fiftieth = fixture.post(REGISTER, &admin, &pairs).await?;
    assert_eq!(fiftieth.status(), StatusCode::OK, "the 50th fits");
    let html = text(fiftieth).await?;
    assert!(html.contains(&en_with(
        keys::WEB_ADMIN_MCP_CONNECTIONS_COUNT,
        &[("count", "50"), ("max", "50")]
    )));
    assert!(
        html.contains("id=\"mcp-register-full\""),
        "the form says it is full"
    );
    let more = [
        ("name", "More"),
        ("redirect_uris", "https://more.example/cb"),
    ];
    let refused = fixture.post(REGISTER, &admin, &more).await?;
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        text(refused)
            .await?
            .contains(&en(keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_FULL))
    );
    assert_eq!(seed.clients()?.clients().len(), 50);
    let entries = fixture.audited("web.mcp_client_register").await?;
    assert!(entries.iter().any(|entry| entry.outcome == "too_many"));
    Ok(())
}

/// Regression (todo 32): a refused form comes back with what was entered escaped.
///
/// A redirect URI that closes the textarea and opens a script, and a name that closes
/// its attribute, answer 422 and the page carries neither as markup.
#[tokio::test]
async fn a_refused_form_comes_back_escaped() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let pairs = [
        ("name", "\"><script>alert(2)</script>"),
        (
            "redirect_uris",
            "https://a.example/cb\n</textarea><script>alert(1)</script>",
        ),
    ];
    let answer = fixture.post(REGISTER, &admin, &pairs).await?;
    assert_eq!(answer.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let html = text(answer).await?;
    assert!(
        html.contains("id=\"mcp-register-uris-error\""),
        "refused: {html}"
    );
    assert!(!html.contains("<script>"), "no script markup: {html}");
    assert!(!html.contains("</textarea><script"), "{html}");
    assert!(
        html.contains("&#60;/textarea&#62;&#60;script&#62;alert(1)&#60;/script&#62;</textarea>"),
        "the entered lines stay text in the textarea: {html}"
    );
    Ok(())
}

/// Regression (todo 32): padded redirect URIs and names are refused as registration does.
///
/// Pre-registration refuses them as `/oauth/register` does and still reads the
/// textarea's lines naturally.
///
/// A redirect line with a leading or trailing space or tab is refused for its
/// characters, a name padded with a tab for its control character; lines separated by
/// CRLF, a trailing line break and blank lines are accepted, and the URIs are stored as
/// written.
#[tokio::test]
async fn padded_lines_and_names_are_refused_as_registration_does() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let admin = fixture.login("admin").await?;
    let characters = en_with(
        keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_REDIRECT,
        &[
            ("item", "1"),
            (
                "what",
                &tr(
                    Locale::En,
                    keys::WEB_ADMIN_MCP_CONNECTIONS_REDIRECT_CHARACTERS,
                    None,
                ),
            ),
        ],
    );
    for padded in [
        "https://a.example/cb\t",
        "\thttps://a.example/cb",
        "https://a.example/cb ",
        " https://a.example/cb",
    ] {
        let pairs = [("name", "Tool"), ("redirect_uris", padded)];
        let answer = fixture.post(REGISTER, &admin, &pairs).await?;
        assert_eq!(
            answer.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{padded:?}"
        );
        assert!(text(answer).await?.contains(&characters), "{padded:?}");
    }
    for name in ["\tTool", "Tool\t"] {
        let pairs = [("name", name), ("redirect_uris", "https://a.example/cb")];
        let answer = fixture.post(REGISTER, &admin, &pairs).await?;
        assert_eq!(
            answer.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{name:?}"
        );
        let html = text(answer).await?;
        assert!(
            html.contains(&en(keys::WEB_ADMIN_MCP_CONNECTIONS_ERROR_NAME)),
            "{name:?}"
        );
    }
    assert!(seed.clients()?.clients().is_empty(), "nothing stored");
    let lines = "https://a.example/cb\r\n\r\n  \r\nhttps://b.example/cb\r\n";
    let pairs = [("name", "Tool"), ("redirect_uris", lines)];
    let answer = fixture.post(REGISTER, &admin, &pairs).await?;
    assert_eq!(answer.status(), StatusCode::OK);
    let clients = seed.clients()?;
    let [client] = clients.clients() else {
        return Err("one client".into());
    };
    assert_eq!(
        client.redirect_uris(),
        ["https://a.example/cb", "https://b.example/cb"]
    );
    assert_eq!(client.name(), Some("Tool"));
    Ok(())
}
