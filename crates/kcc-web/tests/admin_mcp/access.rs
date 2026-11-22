//! Who may open the MCP settings page, the CSRF check of its changes, and what it never
//! renders unescaped.

use axum::http::StatusCode;
use kcc_i18n::keys;
use kcc_web::admin::mcp_control::McpStatus;

use crate::{
    client::{PAGE, status_path},
    fixture::Mcp,
    support::{
        outcome::TestResult,
        page::{en, text},
    },
};

/// Every change of the page: the settings, a reset and an upload.
const CHANGES: [&str; 3] = [PAGE, "/ui/admin/mcp/reset", "/ui/admin/mcp/ca"];

/// Regression (todo 27): only roles holding `ManageMcp` open the page.
///
/// It renders for an administrator and a role holding `ManageMcp`; an operator and a
/// role without it get 403 for every page and change, see no MCP tab, and nothing
/// reaches the listeners.
#[tokio::test]
async fn the_page_renders_only_for_roles_that_manage_mcp() -> TestResult {
    let fixture = Mcp::plain().await?;
    for allowed in ["admin", "mia"] {
        let browser = fixture.login(allowed).await?;
        let html = fixture.html(PAGE, &browser).await?;
        for section in [
            keys::WEB_ADMIN_MCP_TOOLS,
            keys::WEB_ADMIN_MCP_ENDPOINTS,
            keys::WEB_ADMIN_MCP_SIGNIN,
            keys::WEB_ADMIN_MCP_KCC,
            keys::WEB_ADMIN_MCP_IDP,
            keys::WEB_ADMIN_MCP_CERTS,
        ] {
            assert!(html.contains(&en(section)), "{allowed} sees {section:?}");
        }
        assert!(
            html.contains("href=\"/ui/admin/mcp\""),
            "{allowed} has the tab"
        );
    }
    for refused in ["operator", "una"] {
        let browser = fixture.login(refused).await?;
        for path in [
            PAGE.to_owned(),
            status_path(),
            format!("{PAGE}/certificate"),
        ] {
            let page = fixture.get(&path, &browser).await?;
            assert_eq!(page.status(), StatusCode::FORBIDDEN, "{refused} GET {path}");
        }
        let pairs = [("field", "max_result_bytes"), ("max_result_bytes", "2000")];
        for path in CHANGES {
            let change = fixture.post(path, &browser, &pairs).await?;
            assert_eq!(
                change.status(),
                StatusCode::FORBIDDEN,
                "{refused} POST {path}"
            );
        }
    }
    let una = fixture.login("una").await?;
    let users = fixture.html("/ui/admin/users", &una).await?;
    assert!(
        !users.contains("href=\"/ui/admin/mcp\""),
        "no MCP tab for una"
    );
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied");
    assert!(fixture.settings_bytes()?.is_empty(), "nothing saved");
    Ok(())
}

/// Regression (todo 27): every change of the page is refused without the CSRF token and
/// reaches neither the listeners nor the state.
#[tokio::test]
async fn every_change_needs_the_csrf_token() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let pairs = [
        ("field", "max_result_bytes"),
        ("max_result_bytes", "2000"),
        ("key", "max_result_bytes"),
    ];
    for path in CHANGES {
        let refused = fixture.post(path, &admin.tokenless(), &pairs).await?;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "POST {path}");
    }
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied");
    assert!(fixture.settings_bytes()?.is_empty(), "nothing saved");
    let accepted = fixture.post(PAGE, &admin, &pairs[..2]).await?;
    assert_eq!(
        accepted.status(),
        StatusCode::OK,
        "the same change with the token"
    );
    assert_eq!(fixture.stub()?.applied().len(), 1, "applied with the token");
    Ok(())
}

/// Regression (todo 27): values from kcc.toml are escaped wherever the page shows them,
/// and it has no inline script or style.
#[tokio::test]
async fn the_page_escapes_configured_values() -> TestResult {
    let toml = "[mcp.auth.oidc]\naudience = \"<script>alert(1)</script>\"\n\
                role_claim = \"<img src=x>\"\n\
                [[mcp.auth.oidc.role_mappings]]\nclaim_value = \"<b>ops</b>\"\nrole = \"viewer\"\n";
    let fixture = Mcp::build(toml, &[], Some(McpStatus::default())).await?;
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    for raw in ["<script>alert", "<img src=x>", "<b>ops</b>"] {
        assert!(!html.contains(raw), "{raw} is escaped");
    }
    for escaped in [
        "&#60;script&#62;alert(1)",
        "&#60;img src=x&#62;",
        "&#60;b&#62;ops",
    ] {
        assert!(html.contains(escaped), "{escaped} shown");
    }
    assert!(
        !html.contains("<script>") && !html.contains(" style="),
        "no inline script or style"
    );
    Ok(())
}

/// Regression (todo 27): the server page keeps its read-only MCP rows and links to the
/// MCP settings page.
#[tokio::test]
async fn the_server_page_links_to_the_mcp_settings() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let response = fixture.get("/ui/admin/server", &admin).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let html = text(response).await?;
    assert!(
        html.contains(&en(keys::WEB_ADMIN_SERVER_MCP_HTTP)),
        "MCP rows"
    );
    assert!(
        html.contains(&en(keys::WEB_ADMIN_MCP_SERVER_LINK)),
        "link text"
    );
    assert!(
        html.contains(&format!("id=\"server-mcp-link\" href=\"{PAGE}\"")),
        "link to the page"
    );
    let una = fixture.login("una").await?;
    let theirs = fixture.html("/ui/admin/server", &una).await?;
    assert!(
        !theirs.contains("server-mcp-link"),
        "no link without ManageMcp"
    );
    Ok(())
}
