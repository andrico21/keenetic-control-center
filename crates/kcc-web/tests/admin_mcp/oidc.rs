//! The identity provider on the page.
//!
//! Its CA bundle is checked like the client CA and replaced only with the password while a
//! listener signs in with the provider; mappings are limited to the administrator's roles
//! and never twice for one value; the SSRF allowlist has no field.

use axum::http::StatusCode;
use kcc_app::mcp_settings::{idp_ca::oidc_ca_path, keys::KeyPath};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_web::admin::mcp_control::McpStatus;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use serde_json::{Value, json};

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

/// The fields of an identity provider CA bundle upload.
const OIDC: [(&str, &str); 1] = [("kind", "oidc")];

/// Certificate parameters named `name`, a CA when `is_ca`.
fn params(name: &str, is_ca: bool) -> TestResult<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = if is_ca {
        IsCa::Ca(BasicConstraints::Unconstrained)
    } else {
        IsCa::NoCa
    };
    Ok(params)
}

/// A self-signed CA named `name`, as PEM.
fn ca(name: &str) -> TestResult<String> {
    Ok(params(name, true)?
        .self_signed(&KeyPair::generate()?)?
        .pem())
}

/// The status and text of uploading `bytes` with `fields` as `username`.
async fn upload(
    fixture: &Mcp,
    username: &str,
    (fields, bytes): (&[(&str, &str)], &[u8]),
) -> TestResult<(StatusCode, String)> {
    let browser = fixture.login(username).await?;
    let response = fixture.upload(UPLOAD, &browser, (fields, bytes)).await?;
    let status = response.status();
    Ok((status, text(response).await?))
}

/// Regression (todo 33): the identity provider CA bundle passes the client CA's checks.
///
/// A certificate that is not a CA, more than ten, an unreadable certificate block or a
/// private key refuse it with the localized reason, and nothing is stored or handed over.
#[tokio::test]
async fn an_idp_bundle_is_checked_like_the_client_ca() -> TestResult {
    let fixture = Mcp::plain().await?;
    let issuer = Issuer::new(params("issuing CA", true)?, KeyPair::generate()?);
    let leaf = params("idp.example", false)?
        .signed_by(&KeyPair::generate()?, &issuer)?
        .pem();
    let elevens: Vec<String> = (0_u8..11)
        .map(|n| ca(&format!("CA {n}")))
        .collect::<Result<_, _>>()?;
    let garbage =
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n";
    let key = KeyPair::generate()?.serialize_pem();
    for (bytes, (message, value)) in [
        (
            format!("{}{leaf}", ca("Good CA")?),
            (keys::WEB_ADMIN_MCP_MTLS_CA_NOT_CA, Some("2")),
        ),
        (
            elevens.concat(),
            (keys::WEB_ADMIN_MCP_MTLS_CA_COUNT, Some("11")),
        ),
        (
            garbage.to_owned(),
            (keys::WEB_ADMIN_MCP_MTLS_CA_UNREADABLE, Some("1")),
        ),
        (
            format!("{}{key}", ca("CA")?),
            (keys::WEB_ADMIN_MCP_ERROR_UPLOAD_PEM, None),
        ),
    ] {
        let (status, answer) = upload(&fixture, "admin", (&OIDC, bytes.as_bytes())).await?;
        let expected = value.map_or_else(|| en(message), |n| en_with(message, &[("value", n)]));
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
        assert!(answer.contains(&expected), "{expected}: {answer}");
        assert!(!answer.contains("PRIVATE KEY"), "no key echoed");
    }
    assert!(!oidc_ca_path(fixture.store()).exists(), "nothing stored");
    assert_eq!(fixture.stub()?.replaced_idp(), Vec::<bool>::new());
    Ok(())
}

/// Regression (todo 33): while no listener signs in with the provider a bundle is handed
/// over without a password, and the page lists its certificates' subjects, escaped.
#[tokio::test]
async fn an_unused_idp_bundle_is_stored_without_a_password() -> TestResult {
    let fixture = Mcp::plain().await?;
    let bundle = format!("{}{}", ca("<b>IdP</b> root")?, ca("Second IdP CA")?);

    let (status, answer) = upload(&fixture, "admin", (&OIDC, bundle.as_bytes())).await?;

    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(answer.contains(&en(keys::WEB_ADMIN_MCP_CA_SAVED)));
    assert_eq!(fixture.stub()?.replaced_idp(), vec![false]);
    assert_eq!(
        fixture.stub()?.replaced(),
        Vec::<bool>::new(),
        "not the client CA"
    );
    let page = fixture.html(PAGE, &fixture.login("admin").await?).await?;
    let listed = page
        .split_once("id=\"mcp-ca-oidc-subjects\"")
        .ok_or("no subjects list")?
        .1;
    assert!(
        listed.contains("CN=&#60;b&#62;IdP&#60;/b&#62; root"),
        "escaped subject"
    );
    assert!(listed.contains("CN=Second IdP CA"));
    assert!(!page.contains("<b>IdP"), "no raw markup");
    assert!(
        !page.contains("id=\"mcp-ca-oidc-password\""),
        "no password asked"
    );
    Ok(())
}

/// Regression (todo 33): replacing the bundle in use needs the password.
///
/// While a listener signs in with the provider, an upload without the password or with a
/// wrong one hands nothing over (a wrong one is audited); with it the listener restarts.
#[tokio::test]
async fn replacing_an_idp_bundle_in_use_needs_the_password() -> TestResult {
    let fixture = Mcp::build(
        "[mcp.auth.main]\noauth = \"external\"\n",
        &[],
        Some(McpStatus::new()),
    )
    .await?;
    let pem = ca("Replacement IdP CA")?;
    let page = fixture.html(PAGE, &fixture.login("admin").await?).await?;
    assert!(
        page.contains("id=\"mcp-ca-oidc-password\""),
        "password field"
    );
    assert!(
        !page.contains("id=\"mcp-ca-mtls-password\""),
        "the client CA is unused"
    );

    let (missing, answer) = upload(&fixture, "admin", (&OIDC, pem.as_bytes())).await?;
    assert_eq!(missing, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        answer.contains(&en(keys::WEB_ADMIN_MCP_OIDC_CA_PASSWORD)),
        "{answer}"
    );
    let wrong = [("kind", "oidc"), ("password", "not the password")];
    let (refused, wrong_answer) = upload(&fixture, "admin", (&wrong, pem.as_bytes())).await?;
    assert_eq!(refused, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        wrong_answer.contains(&en(keys::WEB_ADMIN_MCP_CONFIRM_WRONG)),
        "{wrong_answer}"
    );
    assert_eq!(fixture.stub()?.replaced_idp(), Vec::<bool>::new());
    assert!(!oidc_ca_path(fixture.store()).exists(), "nothing stored");

    let admin = fixture.login("admin").await?;
    let right = [("kind", "oidc"), ("password", PASSWORD)];
    let started = fixture
        .upload(UPLOAD, &admin, (&right, pem.as_bytes()))
        .await?;
    assert_eq!(started.status(), StatusCode::OK);
    let settled = fixture.settled(&admin).await?;
    assert!(
        settled.contains("web-admin-mcp-restart-applied"),
        "{settled}"
    );
    assert_eq!(fixture.stub()?.replaced_idp(), vec![true]);
    let outcomes: Vec<(String, Value)> = fixture
        .audited("web.mcp_settings")
        .await?
        .into_iter()
        .map(|entry| (entry.outcome, entry.params_redacted))
        .collect();
    let restarted = json!({"changed": ["auth.oidc.ca"], "restarted": ["main"]});
    assert_eq!(
        outcomes,
        vec![
            ("wrong_password".to_owned(), restarted.clone()),
            ("success".to_owned(), restarted)
        ]
    );
    Ok(())
}

/// Regression (todo 33): mappings stay under the actor and the allowlist is not editable.
///
/// A custom role holding `ManageMcp` cannot map a scope to `admin`, a value mapped twice is
/// refused, and the SSRF allowlist has no Web field: nothing is applied.
#[tokio::test]
async fn mappings_stay_under_the_actor_and_the_allowlist_is_not_editable() -> TestResult {
    let fixture = Mcp::plain().await?;
    let mia = fixture.login("mia").await?;
    let admin = fixture.login("admin").await?;
    let scope = [
        ("field", "auth.oidc.scopes"),
        ("scope_name", "mcp"),
        ("scope_role", "admin"),
        ("password", PASSWORD),
    ];
    let (status, refused) = fixture.save(&mia, &scope).await?;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        refused.contains(&en_with(
            keys::WEB_ADMIN_MCP_ERROR_ROLE_ABOVE,
            &[("value", "admin")]
        )),
        "{refused}"
    );
    let twice = [
        ("field", "auth.oidc.role_mappings"),
        ("mapping_claim", "ops"),
        ("mapping_role", "viewer"),
        ("mapping_claim", "ops"),
        ("mapping_role", "admin"),
        ("password", PASSWORD),
    ];
    let (refused_twice, duplicate) = fixture.save(&admin, &twice).await?;
    assert_eq!(
        refused_twice,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{duplicate}"
    );
    let what = tr(Locale::En, keys::WEB_ADMIN_MCP_KEY_OIDC_ROLE_MAPPINGS, None);
    assert!(
        duplicate.contains(&en_with(
            keys::WEB_ADMIN_MCP_ERROR_INVALID,
            &[("what", &what)]
        )),
        "{duplicate}"
    );
    for field in ["auth.oidc.ssrf_allow_hosts", "auth.oidc.ssrf_allow_cidrs"] {
        let pairs = [
            ("field", field),
            (field, "localhost"),
            ("password", PASSWORD),
        ];
        let (unknown, answer) = fixture.save(&admin, &pairs).await?;
        assert_eq!(
            unknown,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{field}: {answer}"
        );
        assert!(field.parse::<KeyPath>().is_err(), "{field}");
    }
    assert!(fixture.stub()?.applied().is_empty(), "nothing applied");
    assert!(fixture.stub()?.restarted().is_empty(), "nothing restarted");
    Ok(())
}
