//! `kcc serve` with MCP client-certificate sign-in: a dedicated listener requiring a
//! certificate from the uploaded CA, a main listener where it is optional (the Web UI
//! keeps working without one), identities namespaced `mtls:<cn>` in the audit log, and the
//! start-up fallback when the main listener's CA file is gone.
//!
//! On Linux every child runs with a 1 MiB main-thread stack (`ulimit -s 1024`), the size
//! Windows gives the main thread.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "serve_mtls/fixture.rs"]
mod fixture;
#[path = "support/master_key.rs"]
mod master_key;
#[path = "serve_mtls/mcp.rs"]
mod mcp;
#[path = "serve_mtls/pki.rs"]
mod pki;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;

use core::error::Error;
use std::fs;

use fixture::{CN, Fixture, url};
use kcc_app::{
    audit::{AuditEntry, read_entries},
    mcp_settings::document::McpSettingsDocument,
    settings::mcp_schema::MtlsMode,
};
use mcp::Session;
use pki::ClientCa;
use reqwest::StatusCode;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// Todo 28: a required client certificate admits only certificates from the uploaded CA.
///
/// The dedicated listener with `mtls = "required"` lists the tools of the default role to
/// a client presenting one; a certificate from another CA and no certificate are refused
/// during the TLS handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_required_listener_admits_only_certificates_from_the_uploaded_ca() -> TestResult {
    let fixture = Fixture::new()?;
    let ([main, dedicated], _server) = fixture.serve_both()?;
    let anonymous = fixture.client(None)?;
    let lab = Session::open(&anonymous, &url(main), Some(&fixture.lab_key)).await?;

    let certified = fixture.client(Some(&fixture.ca))?;
    let session = Session::open(&certified, &url(dedicated), None).await?;

    assert_eq!(session.tool_names().await?, lab.tool_names().await?);
    let stranger = fixture.client(Some(&ClientCa::new("another CA")?))?;
    for (who, client) in [("another CA", &stranger), ("no certificate", &anonymous)] {
        let refused = client
            .get(format!("{}/healthz", url(dedicated)))
            .send()
            .await;
        assert!(refused.is_err(), "{who}: {refused:?}");
    }
    Ok(())
}

/// Todo 28: an optional client certificate on main keeps the Web UI open.
///
/// The Web login page loads without a certificate, an MCP client presenting one is
/// admitted with the default role (the tools of the `lab` role, not those of an admin),
/// and one without either is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_optional_main_listener_serves_the_web_and_certified_mcp() -> TestResult {
    let fixture = Fixture::new()?;
    let ([main, _dedicated], _server) = fixture.serve_both()?;
    let anonymous = fixture.client(None)?;
    let login = anonymous
        .get(format!("{}/ui/login", url(main)))
        .send()
        .await?;
    assert_eq!(login.status(), StatusCode::OK);

    let certified = fixture.client(Some(&fixture.ca))?;
    let session = Session::open(&certified, &url(main), None).await?;
    let lab = Session::open(&anonymous, &url(main), Some(&fixture.lab_key)).await?;
    let admin = Session::open(&anonymous, &url(main), Some(&fixture.admin_key)).await?;

    let tools = session.tool_names().await?;
    assert_eq!(tools, lab.tool_names().await?, "the default role");
    assert_ne!(
        tools,
        admin.tool_names().await?,
        "not the key named like the CN"
    );
    let unsigned = anonymous
        .post(format!("{}/mcp", url(main)))
        .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{}}))
        .send()
        .await?;
    assert_eq!(unsigned.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

/// Todo 28: a certificate whose common name equals an API key's name is audited as
/// `mtls:<cn>` and never marks that key used; the key itself still is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_named_like_a_key_is_audited_as_mtls_and_never_uses_the_key() -> TestResult {
    let fixture = Fixture::new()?;
    let ([main, dedicated], _server) = fixture.serve_both()?;
    let eject = json!({"host": "office", "op": "eject", "name": "usb1", "confirm": true});
    let certified = fixture.client(Some(&fixture.ca))?;
    let session = Session::open(&certified, &url(dedicated), None).await?;

    let refused = session
        .call_tool("kcc_storage_write", eject.clone())
        .await?;

    assert!(
        refused.to_string().contains("destructive_disabled"),
        "{refused}"
    );
    assert_eq!(fixture.last_used()?, None, "the key was marked used");
    let actors = |entries: Vec<AuditEntry>| -> Vec<String> {
        entries
            .into_iter()
            .filter(|entry| entry.action == "mcp.kcc_storage_write")
            .map(|entry| entry.actor.id)
            .collect()
    };
    let state = fixture.state()?;
    assert_eq!(
        actors(read_entries(state.dir())?),
        vec![format!("mtls:{CN}")]
    );

    let anonymous = fixture.client(None)?;
    let keyed = Session::open(&anonymous, &url(main), Some(&fixture.admin_key)).await?;
    let _refused: Value = keyed.call_tool("kcc_storage_write", eject).await?;
    assert!(fixture.last_used()?.is_some(), "the key's own use");
    assert_eq!(
        actors(read_entries(state.dir())?),
        vec![format!("mtls:{CN}"), CN.to_owned()]
    );
    Ok(())
}

/// Todo 28: a state file turning mTLS on for main whose CA file was deleted makes
/// `kcc serve` start with kcc.toml's sign-in settings (mTLS off) and log why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_main_ca_starts_with_the_kcc_toml_sign_in() -> TestResult {
    let fixture = Fixture::new()?;
    let state = fixture.state()?;
    let mut document = McpSettingsDocument::default();
    document.revision = 1;
    document.overrides.auth.main.mtls = Some(MtlsMode::Optional);
    state.write(&document)?;
    fs::remove_file(state.dir().join("mcp").join("mtls-ca.pem"))?;

    let ([main, _dedicated], mut server) = fixture.serve("")?;

    let line = server.until("starting with kcc.toml's")?;
    let event: Value = serde_json::from_str(&line)?;
    let reason = event
        .pointer("/fields/error")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no reason: {line}"))?;
    assert!(reason.contains("mtls-ca.pem"), "{reason}");
    let anonymous = fixture.client(None)?;
    let login = anonymous
        .get(format!("{}/ui/login", url(main)))
        .send()
        .await?;
    assert_eq!(login.status(), StatusCode::OK);
    let keyed = Session::open(&anonymous, &url(main), Some(&fixture.admin_key)).await?;
    assert_ne!(keyed.tool_names().await?, Vec::<String>::new());
    Ok(())
}
