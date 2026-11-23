//! The client CA of the client-certificate sign-in on the page.
//!
//! The upload's CA checks and their localized messages, the stored certificates'
//! subjects, the password a replacement needs while a listener uses client certificates,
//! and the default role limited to the roles the administrator covers.

use axum::http::StatusCode;
use kcc_app::mcp_settings::client_ca::mtls_ca_path;
use kcc_i18n::keys;
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

/// The fields of a client CA upload.
const MTLS: [(&str, &str); 1] = [("kind", "mtls")];

/// The fields of a client CA upload with `password`.
fn with_password(password: &str) -> [(&str, &str); 2] {
    [("kind", "mtls"), ("password", password)]
}

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

/// A leaf certificate signed by a fresh CA, as PEM.
fn leaf() -> TestResult<String> {
    let issuer = Issuer::new(params("issuing CA", true)?, KeyPair::generate()?);
    Ok(params("client", false)?
        .signed_by(&KeyPair::generate()?, &issuer)?
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

/// The `<select>` posting `name` in `page`.
fn select<'page>(page: &'page str, name: &str) -> TestResult<&'page str> {
    let start = page
        .find(&format!("name=\"{name}\""))
        .ok_or_else(|| format!("no {name} select"))?;
    let rest = page.get(start..).ok_or("select")?;
    Ok(rest
        .get(..rest.find("</select>").ok_or("open select")?)
        .ok_or("select")?)
}

/// Regression (todo 28): a client CA upload must hold CA certificates only.
///
/// It is refused, with its localized reason and nothing stored, when it holds a
/// certificate that is not a CA, more than ten certificates, a certificate block that is
/// not a certificate, or a private key.
#[tokio::test]
async fn client_ca_uploads_must_hold_ca_certificates() -> TestResult {
    let fixture = Mcp::plain().await?;
    let elevens: Vec<String> = (0_u8..11)
        .map(|n| ca(&format!("CA {n}")))
        .collect::<Result<_, _>>()?;
    let garbage =
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n";
    let key = KeyPair::generate()?.serialize_pem();
    for (bytes, (message, value)) in [
        (
            format!("{}{}", ca("Good CA")?, leaf()?),
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
        let (status, answer) = upload(&fixture, "admin", (&MTLS, bytes.as_bytes())).await?;
        let expected = value.map_or_else(|| en(message), |n| en_with(message, &[("value", n)]));
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
        assert!(answer.contains(&expected), "{expected}: {answer}");
        assert!(!answer.contains("PRIVATE KEY"), "no key echoed");
    }
    assert!(!mtls_ca_path(fixture.store()).exists(), "nothing stored");
    assert_eq!(
        fixture.stub()?.replaced(),
        Vec::<bool>::new(),
        "nothing handed over"
    );
    Ok(())
}

/// Regression (todo 28): while no listener uses client certificates a CA is stored
/// without a password, and the page lists its certificates' subjects, escaped.
#[tokio::test]
async fn a_stored_client_ca_lists_its_subjects_escaped() -> TestResult {
    let fixture = Mcp::plain().await?;
    let bundle = format!("{}{}", ca("<script>x</script>")?, ca("Second CA")?);

    let (status, answer) = upload(&fixture, "admin", (&MTLS, bundle.as_bytes())).await?;

    assert_eq!(status, StatusCode::OK, "{answer}");
    assert!(answer.contains(&en(keys::WEB_ADMIN_MCP_CA_SAVED)));
    assert_eq!(
        fixture.stub()?.replaced(),
        vec![false],
        "unconfirmed hand-over"
    );
    let page = fixture.html(PAGE, &fixture.login("admin").await?).await?;
    assert!(
        page.contains("CN=&#60;script&#62;x&#60;/script&#62;"),
        "escaped subject"
    );
    assert!(!page.contains("<script>x"), "no raw markup");
    assert!(page.contains("CN=Second CA"));
    assert!(
        !page.contains("id=\"mcp-ca-mtls-password\""),
        "no password asked"
    );
    Ok(())
}

/// Regression (todo 28): replacing a client CA in use needs the password.
///
/// While a listener uses client certificates, an upload without the account's password
/// or with a wrong one hands nothing over (a wrong one is audited); with it the listeners
/// using the CA restart.
#[tokio::test]
async fn replacing_a_client_ca_in_use_needs_the_password() -> TestResult {
    let fixture = Mcp::build(
        "[mcp.auth.main]\nmtls = \"optional\"\n",
        &[],
        Some(McpStatus::new()),
    )
    .await?;
    let pem = ca("Replacement CA")?;
    let page = fixture.html(PAGE, &fixture.login("admin").await?).await?;
    assert!(
        page.contains("id=\"mcp-ca-mtls-password\""),
        "password field"
    );

    let (missing, answer) = upload(&fixture, "admin", (&MTLS, pem.as_bytes())).await?;
    assert_eq!(missing, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        answer.contains(&en(keys::WEB_ADMIN_MCP_MTLS_CA_PASSWORD)),
        "{answer}"
    );
    let wrong = with_password("not the password");
    let (refused, wrong_answer) = upload(&fixture, "admin", (&wrong, pem.as_bytes())).await?;
    assert_eq!(refused, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        wrong_answer.contains(&en(keys::WEB_ADMIN_MCP_CONFIRM_WRONG)),
        "{wrong_answer}"
    );
    assert_eq!(
        fixture.stub()?.replaced(),
        Vec::<bool>::new(),
        "nothing handed over"
    );
    assert!(!mtls_ca_path(fixture.store()).exists(), "nothing stored");

    let admin = fixture.login("admin").await?;
    let right = with_password(PASSWORD);
    let started = fixture
        .upload(UPLOAD, &admin, (&right, pem.as_bytes()))
        .await?;
    assert_eq!(started.status(), StatusCode::OK);
    let settled = fixture.settled(&admin).await?;
    assert!(
        settled.contains("web-admin-mcp-restart-applied"),
        "{settled}"
    );
    assert_eq!(
        fixture.stub()?.replaced(),
        vec![true],
        "confirmed hand-over"
    );
    let outcomes: Vec<(String, Value)> = fixture
        .audited("web.mcp_settings")
        .await?
        .into_iter()
        .map(|entry| (entry.outcome, entry.params_redacted))
        .collect();
    let restarted = json!({"changed": ["auth.mtls.ca"], "restarted": ["main"]});
    assert_eq!(
        outcomes,
        vec![
            ("wrong_password".to_owned(), restarted.clone()),
            ("success".to_owned(), restarted)
        ]
    );
    Ok(())
}

/// Regression (todo 28): the client-certificate default role offers only the roles the
/// signed-in administrator's role covers, plus the current one.
#[tokio::test]
async fn the_default_role_offers_only_roles_the_administrator_covers() -> TestResult {
    let fixture = Mcp::build(
        "[mcp.auth.mtls]\ndefault_role = \"operator\"\n",
        &[],
        Some(McpStatus::new()),
    )
    .await?;
    let mia = fixture.html(PAGE, &fixture.login("mia").await?).await?;
    let admin = fixture.html(PAGE, &fixture.login("admin").await?).await?;

    let offered = select(&mia, "auth.mtls.default_role")?;
    for role in ["viewer", "mcpadmin", "operator"] {
        assert!(
            offered.contains(&format!("value=\"{role}\"")),
            "{role}: {offered}"
        );
    }
    for role in ["admin", "useradmin"] {
        assert!(
            !offered.contains(&format!("value=\"{role}\"")),
            "{role}: {offered}"
        );
    }
    assert!(select(&admin, "auth.mtls.default_role")?.contains("value=\"admin\""));
    Ok(())
}
