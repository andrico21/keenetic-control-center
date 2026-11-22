//! Where a change goes: applied live, or a restart of the listeners it names, and what
//! the page shows and audits when the listeners refuse or revert it.

use axum::http::StatusCode;
use kcc_app::mcp_settings::{ListenerKind, document::McpSettingsDocument, keys::KeyPath};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_web::admin::mcp_control::{McpRefusal, McpStatus};
use serde_json::json;

use crate::{
    client::POLLING,
    fixture::Mcp,
    support::{
        base::PASSWORD,
        outcome::TestResult,
        page::{en, en_with},
    },
};

/// A dedicated listener that signs in with the external identity provider.
const EXTERNAL: &str =
    "[mcp.dedicated]\nenabled = true\n[mcp.auth.dedicated]\noauth = \"external\"\n";

/// Regression (todo 27): a toolset change is applied live, restarts nothing, and its
/// audit entry names the key and no listener.
#[tokio::test]
async fn a_toolset_change_applies_live_without_a_restart() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let pairs = [
        ("field", "toolsets"),
        ("toolsets", "core"),
        ("toolsets", "network-write"),
    ];
    let (status, answer) = fixture.save(&admin, &pairs).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(answer.contains(&en(keys::WEB_ADMIN_MCP_SAVED)), "{answer}");
    assert_eq!(fixture.stub()?.applied().len(), 1, "applied live");
    assert!(fixture.stub()?.restarted().is_empty(), "no restart");
    let saved = fixture
        .store()
        .read::<McpSettingsDocument>()?
        .unwrap_or_default();
    assert_eq!(
        saved.overrides.toolsets,
        Some(vec!["core".to_owned(), "network-write".to_owned()])
    );
    let audited = fixture.audited("web.mcp_settings").await?;
    let entry = audited.last().ok_or("no audit entry")?;
    assert_eq!(
        entry.params_redacted.get("changed"),
        Some(&json!(["toolsets"]))
    );
    assert_eq!(entry.params_redacted.get("restarted"), Some(&json!([])));
    Ok(())
}

/// Regression (todo 27): an identity provider change restarts the listener using it.
///
/// The page answers at once with a polling status, and the audit entry names the key and
/// the listener but never the value.
#[tokio::test]
async fn an_identity_provider_change_restarts_the_listener_using_it() -> TestResult {
    let fixture = Mcp::build(EXTERNAL, &[], Some(McpStatus::default())).await?;
    let admin = fixture.login("admin").await?;
    let audience = format!("aud-{}", rand::random::<u64>());
    let pairs = [
        ("field", "auth.oidc.audience"),
        ("auth.oidc.audience", audience.as_str()),
        ("password", PASSWORD),
    ];
    let (status, answer) = fixture.save(&admin, &pairs).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(answer.contains(POLLING), "the status polls: {answer}");
    assert!(fixture.stub()?.applied().is_empty(), "not applied live");
    let restarted = fixture.stub()?.restarted();
    assert_eq!(
        restarted
            .first()
            .map(|candidate| candidate.restart().to_vec()),
        Some(vec![ListenerKind::Dedicated])
    );
    let settled = fixture.settled(&admin).await?;
    assert!(
        settled.contains(&en(keys::WEB_ADMIN_MCP_RESTART_APPLIED)),
        "{settled}"
    );
    let audited = fixture.audited("web.mcp_settings").await?;
    let entry = audited.last().ok_or("no audit entry")?;
    assert_eq!(entry.outcome, "success");
    assert_eq!(
        entry.params_redacted.get("changed"),
        Some(&json!(["auth.oidc.audience"]))
    );
    assert_eq!(
        entry.params_redacted.get("restarted"),
        Some(&json!(["dedicated"]))
    );
    assert!(
        !fixture.audit_text().await?.contains(&audience),
        "no value audited"
    );
    Ok(())
}

/// Regression (todo 27): an identity provider mapping to a role above the acting role is
/// refused before anything is applied; one to a role it holds is applied.
#[tokio::test]
async fn a_role_mapping_above_the_actor_is_refused() -> TestResult {
    let fixture = Mcp::plain().await?;
    let mia = fixture.login("mia").await?;
    let mapping = |role| {
        [
            ("field", "auth.oidc.role_mappings"),
            ("mapping_claim", "ops"),
            ("mapping_role", role),
            ("password", PASSWORD),
        ]
    };
    let (status, refused) = fixture.save(&mia, &mapping("admin")).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        refused.contains(&en_with(
            keys::WEB_ADMIN_MCP_ERROR_ROLE_ABOVE,
            &[("value", "admin")]
        )),
        "{refused}"
    );
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied");
    let (_, held) = fixture.save(&mia, &mapping("viewer")).await?;
    assert!(held.contains(&en(keys::WEB_ADMIN_MCP_SAVED)), "{held}");
    let applied = fixture.stub()?.applied();
    assert_eq!(
        applied
            .first()
            .map(|candidate| candidate.changed().to_vec()),
        Some(vec![KeyPath::OidcRoleMappings])
    );
    Ok(())
}

/// Regression (todo 27): a restart the listeners revert leaves `mcp_settings.json` byte
/// for byte as it was and shows the localized reason.
#[tokio::test]
async fn a_reverted_restart_leaves_the_settings_file_unchanged() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let (saved, _) = fixture
        .save(
            &admin,
            &[("field", "max_result_bytes"), ("max_result_bytes", "2000")],
        )
        .await?;
    assert_eq!(saved, StatusCode::OK);
    let before = fixture.settings_bytes()?;
    assert!(!before.is_empty(), "a saved file to compare");
    fixture
        .stub()?
        .answer(Some(McpRefusal::Bind(ListenerKind::Dedicated)));
    let pairs = [("field", "dedicated.enabled"), ("dedicated.enabled", "on")];
    let (status, answer) = fixture.save(&admin, &pairs).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(answer.contains(POLLING), "{answer}");
    let settled = fixture.settled(&admin).await?;
    let what = tr(Locale::En, keys::WEB_ADMIN_MCP_LISTENER_DEDICATED, None);
    assert!(
        settled.contains(&en_with(
            keys::WEB_ADMIN_MCP_RESTART_BIND,
            &[("what", &what)]
        )),
        "{settled}"
    );
    assert_eq!(fixture.settings_bytes()?, before, "the file is unchanged");
    let audited = fixture.audited("web.mcp_settings").await?;
    assert_eq!(
        audited.last().map(|entry| entry.outcome.as_str()),
        Some("bind")
    );
    Ok(())
}

/// Regression (todo 27): a live change the listeners refuse because the settings changed
/// meanwhile asks the administrator to reload the page.
#[tokio::test]
async fn a_settings_changed_refusal_asks_for_a_reload() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    fixture.stub()?.answer(Some(McpRefusal::SettingsChanged));
    let (status, answer) = fixture
        .save(
            &admin,
            &[("field", "max_result_bytes"), ("max_result_bytes", "2000")],
        )
        .await?;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        answer.contains(&en(keys::WEB_ADMIN_MCP_RESTART_SETTINGS_CHANGED)),
        "{answer}"
    );
    assert!(fixture.settings_bytes()?.is_empty(), "nothing saved");
    Ok(())
}

/// Regression (todo 27): once a restart applies, the page shows the new values.
///
/// The ended status fragment carries the settings region read again, so a second Save
/// posts the new values, not the ones from before the restart.
#[tokio::test]
async fn an_applied_restart_shows_the_new_values() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let port = "18555";
    let pairs = [
        ("field", "dedicated.enabled"),
        ("dedicated.enabled", "on"),
        ("field", "dedicated.port"),
        ("dedicated.port", port),
    ];
    let (status, answer) = fixture.save(&admin, &pairs).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(answer.contains(POLLING), "{answer}");
    let settled = fixture.settled(&admin).await?;
    assert!(
        settled.contains(&en(keys::WEB_ADMIN_MCP_RESTART_APPLIED)),
        "{settled}"
    );
    assert!(
        settled.contains("id=\"mcp-region\" hx-swap-oob=\"true\""),
        "the region comes along: {settled}"
    );
    assert!(
        settled.contains(&format!(
            "name=\"dedicated.port\" type=\"number\" value=\"{port}\""
        )),
        "the new port: {settled}"
    );
    assert!(
        settled.contains("aria-describedby=\"mcp-dedicated-enabled-source\" checked>"),
        "the listener shows as enabled: {settled}"
    );
    Ok(())
}
