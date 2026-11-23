//! The uploaded client CA of the MCP listeners' mTLS sign-in: checked, then stored.

#![expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]

use core::error::Error;
use std::fs;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use kcc_app::{
    mcp_settings::client_ca::{
        CaError, MTLS_CA, mtls_ca_path, mtls_ca_subjects, restore_mtls_ca, store_mtls_ca,
    },
    persist::StateStore,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    date_time_ymd,
};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The largest file `store_mtls_ca` takes.
const LIMIT: usize = 64 * 1024;

/// A fresh state directory.
fn store() -> TestResult<(TempDir, StateStore)> {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    Ok((temp, state))
}

/// Certificate parameters with the common name `name` and basic constraints `is_ca`.
fn params(name: &str, is_ca: IsCa) -> TestResult<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, name);
    params.distinguished_name = subject;
    params.is_ca = is_ca;
    Ok(params)
}

/// A self-signed CA certificate named `name`, as PEM.
fn ca(name: &str) -> TestResult<String> {
    let key = KeyPair::generate()?;
    Ok(params(name, IsCa::Ca(BasicConstraints::Unconstrained))?
        .self_signed(&key)?
        .pem())
}

/// A leaf certificate named `name` signed by a fresh CA, as PEM.
fn leaf(name: &str) -> TestResult<String> {
    let ca_key = KeyPair::generate()?;
    let issuer = Issuer::new(
        params("issuing CA", IsCa::Ca(BasicConstraints::Unconstrained))?,
        ca_key,
    );
    let key = KeyPair::generate()?;
    Ok(params(name, IsCa::NoCa)?.signed_by(&key, &issuer)?.pem())
}

/// Regression (todo 28): one to ten CA certificates are stored as sent, world-readable
/// (`0644`: certificates are not secret), and their subjects are listed in file order.
#[test]
fn one_to_ten_ca_certificates_are_stored() -> TestResult {
    let (_temp, state) = store()?;
    let single = ca("Single CA")?;
    assert_eq!(
        store_mtls_ca(&state, single.as_bytes())?,
        vec!["CN=Single CA"]
    );
    assert_eq!(fs::read(mtls_ca_path(&state))?, single.as_bytes());

    let bundle: Vec<String> = (1_u8..=10)
        .map(|n| ca(&format!("CA {n}")))
        .collect::<Result<_, _>>()?;
    let subjects = store_mtls_ca(&state, bundle.concat().as_bytes())?;

    let expected: Vec<String> = (1_u8..=10).map(|n| format!("CN=CA {n}")).collect();
    assert_eq!(subjects, expected);
    assert_eq!(mtls_ca_subjects(&state)?, Some(expected));
    assert_eq!(fs::read(mtls_ca_path(&state))?, bundle.concat().as_bytes());
    assert_eq!(
        mtls_ca_path(&state),
        state.dir().join("mcp").join(MTLS_CA),
        "the file's place below the state directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(mtls_ca_path(&state))?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "the CA file is not secret");
    }
    Ok(())
}

/// Regression (todo 28): no file means no subjects.
#[test]
fn no_stored_ca_has_no_subjects() -> TestResult {
    let (_temp, state) = store()?;
    assert_eq!(mtls_ca_subjects(&state)?, None);
    Ok(())
}

/// Regression (todo 28): a certificate that is not a CA (a leaf, a certificate whose
/// basic constraints say `CA:FALSE`, one without basic constraints) is refused, alone or
/// after a CA; nothing is stored.
#[test]
fn certificates_that_are_not_cas_are_refused() -> TestResult {
    let (_temp, state) = store()?;
    let explicit =
        params("Explicit no CA", IsCa::ExplicitNoCa)?.self_signed(&KeyPair::generate()?)?;
    let implicit = params("No constraints", IsCa::NoCa)?.self_signed(&KeyPair::generate()?)?;
    for (pem, index) in [
        (leaf("client")?, 0),
        (format!("{}{}", ca("Good CA")?, leaf("client")?), 1),
        (explicit.pem(), 0),
        (implicit.pem(), 0),
    ] {
        let refused = store_mtls_ca(&state, pem.as_bytes());
        assert!(
            matches!(refused, Err(CaError::NotCa { index: found }) if found == index),
            "{refused:?}"
        );
    }
    assert!(!mtls_ca_path(&state).exists(), "nothing stored");
    Ok(())
}

/// Regression (todo 28): eleven certificates are refused, ten are not.
#[test]
fn more_than_ten_certificates_are_refused() -> TestResult {
    let (_temp, state) = store()?;
    let eleven: Vec<String> = (0_u8..11)
        .map(|n| ca(&format!("CA {n}")))
        .collect::<Result<_, _>>()?;
    let refused = store_mtls_ca(&state, eleven.concat().as_bytes());
    assert!(
        matches!(refused, Err(CaError::Count { found: 11 })),
        "{refused:?}"
    );
    assert!(!mtls_ca_path(&state).exists(), "nothing stored");
    Ok(())
}

/// Regression (todo 28): a file of exactly 64 KiB is taken, one byte more is refused.
#[test]
fn files_over_64_kib_are_refused() -> TestResult {
    let (_temp, state) = store()?;
    let mut largest = ca("Padded CA")?.into_bytes();
    largest.resize(LIMIT, b'\n');
    let mut oversized = largest.clone();
    oversized.push(b'\n');

    let refused = store_mtls_ca(&state, &oversized);

    assert!(matches!(refused, Err(CaError::TooLarge)), "{refused:?}");
    assert!(!mtls_ca_path(&state).exists(), "nothing stored");
    assert_eq!(store_mtls_ca(&state, &largest)?, vec!["CN=Padded CA"]);
    Ok(())
}

/// `pem`'s certificate block re-encoded with two bytes after its DER.
fn trailing(pem: &str) -> TestResult<String> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let mut der = STANDARD.decode(body)?;
    der.extend_from_slice(&[0, 0]);
    Ok(format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(der)
    ))
}

/// Regression (todo 28): text without a certificate block, a private key block beside a
/// CA, a certificate block that is not a certificate and a certificate followed by
/// bytes past its DER are refused.
#[test]
fn files_that_are_not_pem_certificates_are_refused() -> TestResult {
    let (_temp, state) = store()?;
    let key = KeyPair::generate()?.serialize_pem();
    let garbage =
        "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n";
    for (bytes, wanted) in [
        (b"not a certificate".to_vec(), "NotPem"),
        (Vec::new(), "NotPem"),
        (
            format!("{}{key}", ca("CA with key")?).into_bytes(),
            "OtherBlock",
        ),
        (key.into_bytes(), "OtherBlock"),
        (garbage.as_bytes().to_vec(), "Unparsable"),
        (
            trailing(&ca("Trailing bytes CA")?)?.into_bytes(),
            "Unparsable",
        ),
    ] {
        let refused = store_mtls_ca(&state, &bytes);
        let found = match &refused {
            Err(CaError::NotPem) => "NotPem",
            Err(CaError::OtherBlock) => "OtherBlock",
            Err(CaError::Unparsable { index: 0 }) => "Unparsable",
            other => return Err(format!("{wanted}: {other:?}").into()),
        };
        assert_eq!(found, wanted);
        let shown = format!("{refused:?}");
        assert!(!shown.contains("PRIVATE KEY"), "no key echoed: {shown}");
    }
    assert!(!mtls_ca_path(&state).exists(), "nothing stored");
    Ok(())
}

/// Regression (todo 28): an expired CA is stored.
///
/// The plan checks size, count, parse and basic constraints only, not the validity
/// period; the TLS handshake refuses every client certificate chaining to an expired CA,
/// so it admits no one.
#[test]
fn an_expired_ca_is_stored() -> TestResult {
    let (_temp, state) = store()?;
    let mut expired = params("Expired CA", IsCa::Ca(BasicConstraints::Unconstrained))?;
    expired.not_before = date_time_ymd(2001, 1, 1);
    expired.not_after = date_time_ymd(2002, 1, 1);
    let pem = expired.self_signed(&KeyPair::generate()?)?.pem();
    assert_eq!(
        store_mtls_ca(&state, pem.as_bytes())?,
        vec!["CN=Expired CA"]
    );
    Ok(())
}

/// Regression (todo 28): a replacement is atomic.
///
/// A refused file leaves the stored CA as it was, and a new one replaces it whole: the
/// write renames a new file over the old one, so a symbolic link in its place is
/// replaced, never followed.
#[test]
fn a_replacement_is_atomic() -> TestResult {
    let (temp, state) = store()?;
    let first = ca("First CA")?;
    let _subjects = store_mtls_ca(&state, first.as_bytes())?;
    let _refused = store_mtls_ca(&state, leaf("client")?.as_bytes());
    assert_eq!(fs::read(mtls_ca_path(&state))?, first.as_bytes(), "kept");
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let outside = temp.path().join("outside.pem");
        fs::write(&outside, "outside")?;
        fs::remove_file(mtls_ca_path(&state))?;
        symlink(&outside, mtls_ca_path(&state))?;
        let second = ca("Second CA")?;
        let _second_subjects = store_mtls_ca(&state, second.as_bytes())?;
        assert_eq!(
            fs::read_to_string(&outside)?,
            "outside",
            "link not followed"
        );
        assert!(
            !fs::symlink_metadata(mtls_ca_path(&state))?
                .file_type()
                .is_symlink(),
            "the link was replaced by the file"
        );
        assert_eq!(fs::read(mtls_ca_path(&state))?, second.as_bytes());
    }
    let left: Vec<_> = fs::read_dir(state.dir().join("mcp"))?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .filter(|name| name != MTLS_CA)
        .collect();
    assert!(left.is_empty(), "no temporary file left: {left:?}");
    drop(temp);
    Ok(())
}

/// Regression (todo 28): a subject is listed as the certificate names it, markup
/// included; escaping is the page's job.
#[test]
fn subjects_are_returned_verbatim() -> TestResult {
    let (_temp, state) = store()?;
    let name = "<script>alert(1)</script>";
    let subjects = store_mtls_ca(&state, ca(name)?.as_bytes())?;
    assert_eq!(subjects, vec![format!("CN={name}")]);
    Ok(())
}

/// Regression (todo 28): a CA the listeners could not use is undone: the previous file
/// goes back as it was (unchecked: it served before), or the file is removed when there
/// was none.
#[test]
fn a_restore_puts_the_previous_file_back_or_removes_it() -> TestResult {
    let (_temp, state) = store()?;
    let _subjects = store_mtls_ca(&state, ca("New CA")?.as_bytes())?;

    restore_mtls_ca(&state, Some(b"previous bytes"))?;
    assert_eq!(fs::read(mtls_ca_path(&state))?, b"previous bytes");
    restore_mtls_ca(&state, None)?;
    assert!(!mtls_ca_path(&state).exists(), "removed");
    restore_mtls_ca(&state, None)?;
    Ok(())
}

/// Regression (todo 28): a CA file is stored only when the MCP listeners' PEM reader
/// loads the same certificates from it, so it is refused when stored, not when a
/// listener first loads it.
///
/// A header with text after the label (the listeners find no end line) and a lowercase
/// header (no certificate at all) are refused and nothing is written; text after the end
/// line's dashes is read alike by both, so that file is stored.
#[test]
fn certificate_blocks_the_listeners_read_differently_are_refused() -> TestResult {
    let (_temp, state) = store()?;
    let good = ca("Framed CA")?;
    for (from, to) in [
        (
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-x-----",
        ),
        ("-----BEGIN CERTIFICATE-----", "-----begin CERTIFICATE-----"),
    ] {
        let framed = good.replace(from, to);
        let refused = store_mtls_ca(&state, framed.as_bytes());
        assert!(matches!(refused, Err(CaError::NotPem)), "{to}: {refused:?}");
    }
    assert!(!mtls_ca_path(&state).exists(), "nothing stored");
    let trailer = good.replace("-----END CERTIFICATE-----", "-----END CERTIFICATE-----x");
    assert_eq!(
        store_mtls_ca(&state, trailer.as_bytes())?,
        vec!["CN=Framed CA"]
    );
    Ok(())
}
