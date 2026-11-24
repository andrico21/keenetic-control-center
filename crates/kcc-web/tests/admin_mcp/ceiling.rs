//! The role ceiling of the sign-in sources on the page.
//!
//! A role below the roles the identity provider's mappings or the client certificates hand
//! out may not re-point the provider, switch a listener to either source, or replace their
//! CA, and it is told so before any password is asked.

use axum::http::StatusCode;
use kcc_app::mcp_settings::{client_ca::mtls_ca_path, idp_ca::oidc_ca_path};
use kcc_i18n::keys;
use kcc_web::admin::mcp_control::McpStatus;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

use crate::{
    client::PAGE,
    fixture::Mcp,
    support::{
        base::PASSWORD,
        outcome::TestResult,
        page::{en, en_with, text},
    },
};

/// The upload route.
const UPLOAD: &str = "/ui/admin/mcp/ca";

/// The identity provider, with one mapping `ops` to `{role}` and the listener settings
/// `{listeners}` in front.
fn provider(listeners: &str, role: &str) -> String {
    format!(
        "{listeners}[mcp.auth.oidc]\nissuer = \"https://idp.example/realm\"\naudience = \"kcc\"\njwks_uri = \"https://idp.example/jwks\"\nrole_claim = \"groups\"\n[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"ops\"\nrole = \"{role}\"\n"
    )
}

/// A self-signed CA named `name`, as PEM.
fn ca(name: &str) -> TestResult<String> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    Ok(params.self_signed(&KeyPair::generate()?)?.pem())
}

/// The page over `toml` with stand-in listeners that started normally.
// NOT cancel-safe: setup starts the fleet's tasks.
async fn page(toml: &str) -> TestResult<Mcp> {
    Mcp::build(toml, &[], Some(McpStatus::new())).await
}

/// The status and text of uploading a fresh CA as `kind`, with `password` when given, as
/// `username`.
// NOT cancel-safe: a dropped upload may still be handed over.
async fn upload(
    fixture: &Mcp,
    username: &str,
    (kind, password): (&str, Option<&str>),
) -> TestResult<(StatusCode, String)> {
    let browser = fixture.login(username).await?;
    let mut fields = vec![("kind", kind)];
    fields.extend(password.map(|typed| ("password", typed)));
    let pem = ca("Uploaded CA")?;
    let response = fixture
        .upload(UPLOAD, &browser, (&fields, pem.as_bytes()))
        .await?;
    let status = response.status();
    Ok((status, text(response).await?))
}

/// The provider refusal naming `admin`, in English.
fn provider_above() -> String {
    en_with(keys::WEB_ADMIN_MCP_OIDC_ROLE_ABOVE, &[("value", "admin")])
}

/// Regression (todo 33): re-pointing the provider is refused above the actor.
///
/// `mia` (Read and `ManageMcp`) cannot change the issuer or switch the main listener to the
/// provider while kcc.toml maps `ops` to `admin`; nothing reaches the listeners. With the
/// mapping on `viewer` the same issuer change is applied.
#[tokio::test]
async fn re_pointing_the_provider_is_refused_above_the_actor() -> TestResult {
    let fixture = page(&provider("", "admin")).await?;
    let mia = fixture.login("mia").await?;
    let issuer = [
        ("field", "auth.oidc.issuer"),
        ("auth.oidc.issuer", "https://attacker.example/realm"),
        ("password", PASSWORD),
    ];
    let external = [
        ("field", "auth.main.oauth"),
        ("auth.main.oauth", "external"),
        ("password", PASSWORD),
    ];
    for pairs in [&issuer, &external] {
        let (status, refused) = fixture.save(&mia, pairs).await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
        assert!(refused.contains(&provider_above()), "{refused}");
    }
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied");
    assert!(fixture.stub()?.restarted().is_empty(), "nothing restarted");

    let within = page(&provider("", "viewer")).await?;
    let (_, saved) = within.save(&within.login("mia").await?, &issuer).await?;
    assert!(saved.contains(&en(keys::WEB_ADMIN_MCP_SAVED)), "{saved}");
    Ok(())
}

/// Regression (todo 33): the provider's CA bundle is refused above the actor.
///
/// `mia` cannot replace it while a mapping hands out `admin`, with or without its password
/// and whether or not a listener uses the provider: refused before the password step (no
/// audit entry, nothing handed over). An administrator reaches the password step; with the
/// mapping on `viewer` `mia` replaces it.
#[tokio::test]
async fn an_idp_bundle_is_refused_above_the_actor_before_the_password() -> TestResult {
    for listeners in ["[mcp.auth.main]\noauth = \"external\"\n", ""] {
        let fixture = page(&provider(listeners, "admin")).await?;
        for password in [None, Some(PASSWORD)] {
            let (status, refused) = upload(&fixture, "mia", ("oidc", password)).await?;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
            assert!(
                refused.contains(&provider_above()),
                "{listeners}: {refused}"
            );
        }
        assert_eq!(fixture.stub()?.replaced_idp(), Vec::<bool>::new());
        assert!(!oidc_ca_path(fixture.store()).exists(), "nothing stored");
        let audited = fixture.audited("web.mcp_settings").await?;
        assert_eq!(audited.len(), 0, "nothing audited");
    }
    let used = page(&provider(
        "[mcp.auth.main]\noauth = \"external\"\n",
        "admin",
    ))
    .await?;
    let (_, asked) = upload(&used, "admin", ("oidc", None)).await?;
    assert!(
        asked.contains(&en(keys::WEB_ADMIN_MCP_OIDC_CA_PASSWORD)),
        "{asked}"
    );
    let within = page(&provider("", "viewer")).await?;
    let (status, saved) = upload(&within, "mia", ("oidc", None)).await?;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(within.stub()?.replaced_idp(), vec![false]);
    Ok(())
}

/// Regression (todo 33, the client CA of todo 28): the client CA is refused above the actor.
///
/// While client certificates get `admin` (kcc.toml `default_role`), `mia` can neither
/// replace the client CA (refused before the password step) nor switch the main listener to
/// certificates; an administrator replaces it, and under the default role `viewer` so does
/// `mia`.
#[tokio::test]
async fn the_client_ca_is_refused_above_the_actor() -> TestResult {
    let fixture = page("[mcp.auth.mtls]\ndefault_role = \"admin\"\n").await?;
    let certificates_above = en_with(keys::WEB_ADMIN_MCP_MTLS_ROLE_ABOVE, &[("value", "admin")]);
    for password in [None, Some(PASSWORD)] {
        let (status, refused) = upload(&fixture, "mia", ("mtls", password)).await?;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
        assert!(refused.contains(&certificates_above), "{refused}");
    }
    assert_eq!(fixture.stub()?.replaced(), Vec::<bool>::new());
    assert!(!mtls_ca_path(fixture.store()).exists(), "nothing stored");
    let mia = fixture.login("mia").await?;
    let optional = [
        ("field", "auth.main.mtls"),
        ("auth.main.mtls", "optional"),
        ("password", PASSWORD),
    ];
    let (status, refused) = fixture.save(&mia, &optional).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{refused}");
    assert!(refused.contains(&certificates_above), "{refused}");
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied");

    let (admin_status, saved) = upload(&fixture, "admin", ("mtls", None)).await?;
    assert_eq!(admin_status, StatusCode::OK, "{saved}");
    let plain = Mcp::plain().await?;
    let (mia_status, mia_saved) = upload(&plain, "mia", ("mtls", None)).await?;
    assert_eq!(mia_status, StatusCode::OK, "{mia_saved}");
    assert_eq!(plain.stub()?.replaced(), vec![false]);
    Ok(())
}

/// Regression (todo 33): a dedicated listener on the provider makes the page ask for it.
///
/// It signs in with the provider and so uses its CA bundle: the upload form carries the
/// password field.
#[tokio::test]
async fn a_dedicated_listener_on_the_provider_asks_for_the_password() -> TestResult {
    let fixture =
        page("[mcp.dedicated]\nenabled = true\n[mcp.auth.dedicated]\noauth = \"external\"\n")
            .await?;

    let html = fixture.html(PAGE, &fixture.login("admin").await?).await?;

    assert!(
        html.contains("id=\"mcp-ca-oidc-password\""),
        "password field"
    );
    Ok(())
}
