//! The identity provider's CA bundle and the `[mcp.auth.oidc]` rules.
//!
//! The bundle is checked as the client CA and stored apart from it, algorithms are limited
//! to asymmetric ones, and no claim value or scope is mapped twice.

#![expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]

use core::error::Error;
use std::fs;

use kcc_app::{
    mcp_settings::{
        client_ca::{CaError, mtls_ca_path},
        idp_ca::{
            OIDC_CA, oidc_ca_path, oidc_ca_subjects, read_oidc_ca, restore_oidc_ca, store_oidc_ca,
        },
    },
    persist::StateStore,
    settings::{Config, ConfigError},
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A fresh state directory.
fn store() -> TestResult<(TempDir, StateStore)> {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    Ok((temp, state))
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

/// Regression (todo 33): a bundle is stored as `<state>/mcp/oidc-ca.pem`, apart from the
/// client CA.
///
/// Its subjects are listed; a bundle the checks refuse is never written and the previous
/// one stays; a restore puts the previous bytes back or removes the file.
#[test]
fn an_idp_bundle_is_checked_stored_and_restored() -> TestResult {
    let (_temp, state) = store()?;
    let first = ca("IdP root")?;

    let subjects = store_oidc_ca(&state, first.as_bytes())?;

    assert_eq!(subjects, vec!["CN=IdP root".to_owned()]);
    assert_eq!(oidc_ca_path(&state), state.dir().join("mcp").join(OIDC_CA));
    assert_eq!(fs::read_to_string(oidc_ca_path(&state))?, first);
    assert!(!mtls_ca_path(&state).exists(), "not the client CA");
    assert_eq!(
        oidc_ca_subjects(&state)?,
        Some(vec!["CN=IdP root".to_owned()])
    );
    let issuer = Issuer::new(params("issuing CA", true)?, KeyPair::generate()?);
    let leaf = params("idp.example", false)?
        .signed_by(&KeyPair::generate()?, &issuer)?
        .pem();
    for (refused, expected) in [
        (leaf, "NotCa"),
        ("not a certificate".to_owned(), "NotPem"),
        ("x".repeat(64 * 1024 + 1), "TooLarge"),
    ] {
        let error = store_oidc_ca(&state, refused.as_bytes());
        let name = match error {
            Err(CaError::NotCa { index: 0 }) => "NotCa",
            Err(CaError::NotPem) => "NotPem",
            Err(CaError::TooLarge) => "TooLarge",
            other => return Err(format!("{expected}: {other:?}").into()),
        };
        assert_eq!(name, expected);
        assert_eq!(
            fs::read_to_string(oidc_ca_path(&state))?,
            first,
            "{expected}"
        );
    }
    let second = ca("Second IdP root")?;
    let _subjects = store_oidc_ca(&state, second.as_bytes())?;
    restore_oidc_ca(&state, Some(first.as_bytes()))?;
    assert_eq!(read_oidc_ca(&state)?, Some(first.into_bytes()));
    restore_oidc_ca(&state, None)?;
    assert_eq!(read_oidc_ca(&state)?, None);
    assert_eq!(oidc_ca_subjects(&state)?, None);
    Ok(())
}

/// The `[mcp.auth.oidc]` field a kcc.toml `oidc` table is refused for, if any.
fn refused_field(oidc: &str) -> TestResult<Option<String>> {
    let config = Config::from_toml_str(&format!("[mcp.auth.oidc]\n{oidc}"))?;
    match config.validate() {
        Ok(()) => Ok(None),
        Err(ConfigError::Invalid { field, reason: _ }) => Ok(Some(field)),
        Err(other) => Err(other.into()),
    }
}

/// Regression (todo 33): `allowed_algorithms` takes only the asymmetric algorithms the kit
/// knows, in any case; `HS256`, `none` and unknown names are refused.
#[test]
fn only_asymmetric_algorithms_are_allowed() -> TestResult {
    assert_eq!(
        refused_field("allowed_algorithms = [\"ES256\", \"eddsa\", \"RS256\", \"PS512\"]")?,
        None
    );
    for name in ["HS256", "none", "ES512", "hs384"] {
        assert_eq!(
            refused_field(&format!("allowed_algorithms = [\"{name}\"]"))?.as_deref(),
            Some("mcp.auth.oidc.allowed_algorithms"),
            "{name}"
        );
    }
    Ok(())
}

/// Regression (todo 33): a claim value or scope mapped twice is refused: the provider's
/// first match would win, so a second mapping could hide a role behind another.
#[test]
fn a_value_mapped_twice_is_refused() -> TestResult {
    let twice = |table: &str, key: &str| {
        format!(
            "[[mcp.auth.oidc.{table}]]\n{key} = \"ops\"\nrole = \"viewer\"\n\n[[mcp.auth.oidc.{table}]]\n{key} = \"ops\"\nrole = \"admin\"\n"
        )
    };
    let distinct = "[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"ops\"\nrole = \"viewer\"\n\n[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"dev\"\nrole = \"viewer\"\n";
    assert_eq!(refused_field(distinct)?, None);
    assert_eq!(
        refused_field(&twice("role_mappings", "claim_value"))?.as_deref(),
        Some("mcp.auth.oidc.role_mappings")
    );
    assert_eq!(
        refused_field(&twice("scopes", "scope"))?.as_deref(),
        Some("mcp.auth.oidc.scopes")
    );
    Ok(())
}

/// Regression (todo 33): kcc's checks refuse what the kit refuses at build.
///
/// An algorithm name with spaces around it, and an issuer or JWKS URL carrying a user name
/// or password, each naming its field; a port is fine.
#[test]
fn values_the_kit_refuses_are_refused_by_kcc() -> TestResult {
    for (oidc, field) in [
        ("allowed_algorithms = [\" es256 \"]", "allowed_algorithms"),
        ("allowed_algorithms = [\"ES256 \"]", "allowed_algorithms"),
        (
            "jwks_uri = \"https://user:word@idp.example/jwks\"",
            "jwks_uri",
        ),
        ("jwks_uri = \"https://user@idp.example/jwks\"", "jwks_uri"),
        ("issuer = \"https://user:word@idp.example/realm\"", "issuer"),
    ] {
        assert_eq!(
            refused_field(oidc)?,
            Some(format!("mcp.auth.oidc.{field}")),
            "{oidc}"
        );
    }
    assert_eq!(
        refused_field(
            "issuer = \"https://idp.example:8443/realm\"\njwks_uri = \"https://idp.example:8443/jwks\"\nallowed_algorithms = [\"es256\"]"
        )?,
        None
    );
    Ok(())
}
