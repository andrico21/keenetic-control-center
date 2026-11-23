//! The CA uploads (size and PEM shape only, no paths) and the dedicated listener's
//! self-signed certificate, offered without its key.

use core::{iter::repeat_with, str};
use std::fs;

use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use kcc_i18n::keys;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use sha2::{Digest as _, Sha256};

use crate::{
    client::PAGE,
    fixture::Mcp,
    support::{
        outcome::TestResult,
        page::{en, text},
    },
};

/// The form fields and the file bytes of one upload.
type Upload<'fields> = (&'fields [(&'fields str, &'fields str)], Vec<u8>);

/// The upload route.
const UPLOAD: &str = "/ui/admin/mcp/ca";

/// The largest file the upload takes.
const LIMIT: usize = 64 * 1024;

/// One PEM block labelled `label` around `der`, base64 in 64-column lines.
fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .filter_map(|line| str::from_utf8(line).ok())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// `count` random bytes, built at run time.
fn random(count: usize) -> Vec<u8> {
    repeat_with(rand::random::<u8>).take(count).collect()
}

/// Regression (todo 27): a CA upload is checked for size and PEM shape.
///
/// It is refused when it is over 64 KiB, not PEM, holds anything besides certificates
/// (the private key is never echoed), or carries a path field; a certificate bundle
/// within the limit is stored for its listener (todo 28: a client CA must also hold CA
/// certificates, which `mtls.rs` covers).
#[tokio::test]
async fn a_ca_upload_is_checked_for_size_and_shape() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let key = pem("PRIVATE KEY", &random(48));
    let certificate = pem("CERTIFICATE", &random(300));
    let mut oversized = certificate.clone().into_bytes();
    oversized.resize(LIMIT.saturating_add(1), b'\n');
    let client_ca = CertificateParams::new(Vec::<String>::new())
        .and_then(|mut params| {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.self_signed(&KeyPair::generate()?)
        })?
        .pem();
    let refused: [Upload<'_>; 5] = [
        (&[("kind", "mtls")], oversized),
        (&[("kind", "mtls")], b"not a certificate".to_vec()),
        (
            &[("kind", "oidc")],
            format!("{certificate}{key}").into_bytes(),
        ),
        (
            &[("kind", "mtls"), ("path", "/etc/ssl/ca.pem")],
            client_ca.clone().into_bytes(),
        ),
        (&[("kind", "elsewhere")], certificate.clone().into_bytes()),
    ];
    for (fields, bytes) in refused {
        let response = fixture.upload(UPLOAD, &admin, (fields, &bytes)).await?;
        let status = response.status();
        let answer = text(response).await?;
        assert!(status.is_client_error(), "{fields:?}: {status}");
        assert!(!answer.contains("PRIVATE KEY"), "{fields:?}: no key echoed");
    }
    let stored = fixture.state_file("mcp");
    assert!(!stored.join("mtls-ca.pem").exists() && !stored.join("oidc-ca.pem").exists());
    assert!(
        !fixture.audit_text().await?.contains("PRIVATE KEY"),
        "no key audited"
    );
    for (kind, file, shape) in [
        ("mtls", "mtls-ca.pem", &client_ca),
        ("oidc", "oidc-ca.pem", &certificate),
    ] {
        let mut bundle = shape.clone().into_bytes();
        bundle.resize(LIMIT, b'\n');
        let response = fixture
            .upload(UPLOAD, &admin, (&[("kind", kind)], &bundle))
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "{kind}");
        assert!(
            text(response)
                .await?
                .contains(&en(keys::WEB_ADMIN_MCP_CA_SAVED))
        );
        assert_eq!(
            fs::read(stored.join(file))?,
            bundle,
            "{kind} stored as sent"
        );
    }
    let audited = fixture.audited("web.mcp_settings").await?;
    assert_eq!(
        audited
            .iter()
            .filter(|entry| entry.outcome == "success")
            .count(),
        2
    );
    assert!(
        !fixture.audit_text().await?.contains(&certificate),
        "no file audited"
    );
    Ok(())
}

/// Regression (todo 28): the upload's body limit refuses a 1 MiB request before the
/// handler reads it (413, nothing stored or audited), while a client CA padded to the
/// 64 KiB file limit is still taken.
#[tokio::test]
async fn an_upload_over_the_body_limit_is_refused_unread() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let client_ca = CertificateParams::new(Vec::<String>::new())
        .and_then(|mut params| {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.self_signed(&KeyPair::generate()?)
        })?
        .pem()
        .into_bytes();
    let mut huge = client_ca.clone();
    huge.resize(1024 * 1024, b'\n');

    let refused = fixture
        .upload(UPLOAD, &admin, (&[("kind", "mtls")], &huge))
        .await?;

    assert_eq!(refused.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!fixture.state_file("mcp").join("mtls-ca.pem").exists());
    assert_eq!(
        fixture.audited("web.mcp_settings").await?.len(),
        0,
        "nothing audited"
    );
    let mut largest = client_ca;
    largest.resize(LIMIT, b'\n');
    let taken = fixture
        .upload(UPLOAD, &admin, (&[("kind", "mtls")], &largest))
        .await?;
    assert_eq!(taken.status(), StatusCode::OK);
    assert_eq!(
        fs::read(fixture.state_file("mcp").join("mtls-ca.pem"))?,
        largest
    );
    Ok(())
}

/// Regression (todo 27): the page shows the self-signed certificate's SHA-256 fingerprint
/// and offers the certificate for download, never its key.
#[tokio::test]
async fn the_self_signed_certificate_is_offered_without_its_key() -> TestResult {
    let fixture = Mcp::plain().await?;
    let admin = fixture.login("admin").await?;
    let page = fixture.html(PAGE, &admin).await?;
    assert!(
        page.contains(&en(keys::WEB_ADMIN_MCP_CERT_NONE)),
        "none yet"
    );
    let missing = fixture.get(&format!("{PAGE}/certificate"), &admin).await?;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let der = random(400);
    let certificate = pem("CERTIFICATE", &der);
    let key = pem("PRIVATE KEY", &random(48));
    let directory = fixture.state_file("mcp");
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("dedicated-cert.pem"), &certificate)?;
    fs::write(directory.join("dedicated-key.pem"), &key)?;
    let fingerprint = Sha256::digest(&der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let shown = fixture.html(PAGE, &admin).await?;
    assert!(shown.contains(&fingerprint), "fingerprint shown");
    assert!(
        shown.contains(&format!("href=\"{PAGE}/certificate\"")),
        "download link"
    );
    assert!(!shown.contains("PRIVATE KEY"), "no key on the page");
    let download = fixture.get(&format!("{PAGE}/certificate"), &admin).await?;
    assert_eq!(download.status(), StatusCode::OK);
    let body = text(download).await?;
    assert_eq!(body, certificate, "the certificate as stored");
    Ok(())
}
