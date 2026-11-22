//! Where each value comes from: environment and locked values are text only, and a value
//! set on the Web can be reset to kcc.toml.

use axum::http::StatusCode;
use kcc_app::mcp_settings::{
    document::{McpOverrides, McpSettingsDocument},
    keys::KeyPath,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_web::admin::mcp_control::McpStatus;

use crate::{
    client::PAGE,
    fixture::Mcp,
    support::{
        outcome::TestResult,
        page::{en, en_with, text},
    },
};

/// Regression (todo 27): a value an environment variable or `[mcp] locked` sets has no
/// form control, shows its source, and a forged change of it is refused unapplied.
#[tokio::test]
async fn environment_and_locked_values_are_read_only() -> TestResult {
    let toml = "[mcp]\nlocked = [\"read_only\"]\nread_only = true\n";
    let env = [("KCC_MCP_STDIO_ENABLED", "false")];
    let fixture = Mcp::build(toml, &env, Some(McpStatus::default())).await?;
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    for key in ["read_only", "stdio_enabled"] {
        assert!(
            !html.contains(&format!("name=\"{key}\"")),
            "no control for {key}"
        );
        assert!(
            !html.contains(&format!("value=\"{key}\"")),
            "{key} not posted"
        );
    }
    assert!(
        html.contains(&en(keys::WEB_ADMIN_MCP_SOURCE_LOCKED)),
        "locked"
    );
    assert!(
        html.contains(&en(keys::WEB_ADMIN_MCP_SOURCE_ENV)),
        "environment"
    );
    assert!(
        html.contains("name=\"allow_destructive\""),
        "an editable key keeps its control"
    );
    let forged = [
        (
            [("field", "read_only")],
            keys::WEB_ADMIN_MCP_ERROR_LOCKED,
            keys::WEB_ADMIN_MCP_KEY_READ_ONLY,
        ),
        (
            [("field", "stdio_enabled")],
            keys::WEB_ADMIN_MCP_ERROR_ENV,
            keys::WEB_ADMIN_MCP_KEY_STDIO_ENABLED,
        ),
    ];
    for (pairs, refusal, label) in forged {
        let (status, answer) = fixture.save(&admin, &pairs).await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{pairs:?}");
        let what = tr(Locale::En, label, None);
        assert!(
            answer.contains(&en_with(refusal, &[("what", &what)])),
            "{pairs:?}: {answer}"
        );
    }
    let path = [
        ("field", "max_result_bytes"),
        ("max_result_bytes", "4096"),
        ("path", "/etc/kcc/kcc.toml"),
    ];
    let (status, answer) = fixture.save(&admin, &path).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "a path field");
    assert!(
        answer.contains(&en(keys::WEB_ADMIN_MCP_ERROR_FIELDS)),
        "{answer}"
    );
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied");
    assert!(fixture.stub()?.restarted().is_empty(), "nothing restarted");
    Ok(())
}

/// Regression (todo 27): a value set on the Web says so and offers a reset; a value
/// from kcc.toml or the default offers none, and the reset goes to the listeners.
#[tokio::test]
async fn a_value_set_here_offers_a_reset_to_kcc_toml() -> TestResult {
    let fixture = Mcp::build(
        "[mcp]\nread_only = false\n",
        &[],
        Some(McpStatus::default()),
    )
    .await?;
    let mut overrides = McpOverrides::default();
    overrides.max_result_bytes = Some(2000);
    let mut document = McpSettingsDocument::default();
    document.revision = 1;
    document.overrides = overrides;
    fixture.store().write(&document)?;
    let admin = fixture.login("admin").await?;
    let html = fixture.html(PAGE, &admin).await?;
    assert!(
        html.contains(&en(keys::WEB_ADMIN_MCP_SOURCE_STATE)),
        "overridden"
    );
    assert!(
        html.contains(&en(keys::WEB_ADMIN_MCP_SOURCE_TOML)),
        "kcc.toml"
    );
    assert!(
        html.contains("name=\"key\" value=\"max_result_bytes\""),
        "reset of the overridden value"
    );
    for kept in ["read_only", "allow_destructive"] {
        assert!(
            !html.contains(&format!("name=\"key\" value=\"{kept}\"")),
            "no reset of {kept}"
        );
    }
    let reset = fixture
        .post(
            &format!("{PAGE}/reset"),
            &admin,
            &[("key", "max_result_bytes")],
        )
        .await?;
    assert_eq!(reset.status(), StatusCode::OK);
    let applied = fixture.stub()?.applied();
    assert_eq!(applied.len(), 1, "the reset went to the listeners");
    assert_eq!(
        applied
            .first()
            .map(|candidate| candidate.changed().to_vec()),
        Some(vec![KeyPath::MaxResultBytes])
    );
    let saved = fixture
        .store()
        .read::<McpSettingsDocument>()?
        .unwrap_or_default();
    assert_eq!(
        saved.overrides.max_result_bytes, None,
        "kcc.toml applies again"
    );
    Ok(())
}

/// The settings revision the page's forms carry.
fn revision(html: &str) -> TestResult<String> {
    let (_, tail) = html
        .split_once("name=\"revision\" value=\"")
        .ok_or("no revision field")?;
    Ok(tail.split_once('"').ok_or("unterminated")?.0.to_owned())
}

/// Regression (todo 27): a change or reset from a stale page asks for a reload.
///
/// A form rendered before another save carries the older settings revision; its change
/// and its reset are refused with the reload message and `mcp_settings.json` stays as the
/// other save left it, while a form of the current revision is applied.
#[tokio::test]
async fn a_change_from_a_stale_page_asks_for_a_reload() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let stale = revision(&fixture.html(PAGE, &admin).await?)?;
    let current = [
        ("revision", stale.as_str()),
        ("field", "max_result_bytes"),
        ("max_result_bytes", "4096"),
    ];
    let (applied, answer) = fixture.save(&admin, &current).await?;
    assert_eq!(applied, StatusCode::OK, "{answer}");
    assert!(answer.contains(&en(keys::WEB_ADMIN_MCP_SAVED)), "{answer}");
    let fresh = revision(&fixture.html(PAGE, &admin).await?)?;
    assert_ne!(fresh, stale, "the save raised the revision");
    let saved = fixture.settings_bytes()?;
    let reload = en(keys::WEB_ADMIN_MCP_RESTART_SETTINGS_CHANGED);
    let change = [
        ("revision", stale.as_str()),
        ("field", "max_result_bytes"),
        ("max_result_bytes", "32768"),
    ];
    let (status, refused) = fixture.save(&admin, &change).await?;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert!(refused.contains(&reload), "{refused}");
    let reset = fixture
        .post(
            &format!("{PAGE}/reset"),
            &admin,
            &[("revision", stale.as_str()), ("key", "max_result_bytes")],
        )
        .await?;
    assert_eq!(reset.status(), StatusCode::CONFLICT);
    assert!(text(reset).await?.contains(&reload), "reset refused");
    assert_eq!(fixture.settings_bytes()?, saved, "the file is unchanged");
    assert_eq!(fixture.stub()?.applied().len(), 1, "only the current save");
    Ok(())
}
