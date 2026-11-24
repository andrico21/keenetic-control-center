//! Who may use the connections tab: `ManageMcp` for the page and every change, the CSRF
//! token on every change, and nothing changes for anyone refused.

use axum::http::StatusCode;

use crate::{fixture::Mcp, seed::Seed, support::outcome::TestResult};

/// Every change of the tab as `(path, confirmed form)` for a grant of `alice` and its
/// client.
fn changes(grant: &str, client: &str) -> Vec<(String, Vec<(&'static str, &'static str)>)> {
    vec![
        (
            format!("/ui/admin/mcp/connections/revoke?grant={grant}"),
            vec![("confirm", "yes")],
        ),
        (
            "/ui/admin/mcp/connections/revoke-account?account=alice".to_owned(),
            vec![
                ("confirm", "yes"),
                ("object", "alice"),
                ("confirm_name", "alice"),
            ],
        ),
        (
            format!("/ui/admin/mcp/clients/delete?client={client}"),
            vec![("confirm", "yes")],
        ),
        (
            "/ui/admin/mcp/clients".to_owned(),
            vec![("name", "Tool"), ("redirect_uris", "https://a.example/cb")],
        ),
    ]
}

/// Regression (todo 32): only `ManageMcp` opens the tab and its changes.
///
/// An operator, a viewer and a role without `ManageMcp` get 403 on
/// the tab and on every change, see no MCP tab, and the grant, the client and the client
/// count stay as they were; a role holding `ManageMcp` opens it.
#[tokio::test]
async fn only_manage_mcp_opens_the_tab_and_its_changes() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let grant = seed.grant(&client, "alice")?;
    for refused in ["operator", "viewer", "una"] {
        let browser = fixture.login(refused).await?;
        let page = fixture.get("/ui/admin/mcp/connections", &browser).await?;
        assert_eq!(page.status(), StatusCode::FORBIDDEN, "{refused} GET");
        for (path, pairs) in changes(grant.id(), client.id()) {
            let answer = fixture.post(&path, &browser, &pairs).await?;
            assert_eq!(
                answer.status(),
                StatusCode::FORBIDDEN,
                "{refused} POST {path}"
            );
        }
    }
    assert!(seed.live(grant.id())?, "the grant stays");
    assert_eq!(
        seed.clients()?.clients().len(),
        1,
        "nothing added or deleted"
    );
    let mia = fixture.login("mia").await?;
    let html = fixture.html("/ui/admin/mcp/connections", &mia).await?;
    assert!(
        html.contains("id=\"mcp-connections-region\""),
        "ManageMcp opens it"
    );
    Ok(())
}

/// Regression (todo 32): every change of the tab is refused without the CSRF token, and
/// nothing changes.
#[tokio::test]
async fn every_change_needs_the_csrf_token() -> TestResult {
    let fixture = Mcp::plain().await?;
    let seed = Seed::new(fixture.store())?;
    let client = seed.client(Some("Claude Code"), "http://127.0.0.1:9/cb")?;
    let grant = seed.grant(&client, "alice")?;
    let admin = fixture.login("admin").await?;
    for (path, pairs) in changes(grant.id(), client.id()) {
        let answer = fixture.post(&path, &admin.tokenless(), &pairs).await?;
        assert_eq!(answer.status(), StatusCode::FORBIDDEN, "POST {path}");
    }
    assert!(seed.live(grant.id())?, "the grant stays");
    assert_eq!(
        seed.clients()?.clients().len(),
        1,
        "nothing added or deleted"
    );
    for (path, pairs) in changes(grant.id(), client.id()).into_iter().rev() {
        let answer = fixture.post(&path, &admin, &pairs).await?;
        assert_ne!(
            answer.status(),
            StatusCode::FORBIDDEN,
            "POST {path} with the token"
        );
    }
    Ok(())
}
