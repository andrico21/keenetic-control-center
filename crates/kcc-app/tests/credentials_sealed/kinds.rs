//! One sealed record per credential kind, each bound to its router and kind; password
//! records keep their original name and associated data.

use std::fs;

use kcc_app::{
    credentials::{CredentialError, CredentialKind, CredentialStore},
    secrets::MasterKey,
};
use secrecy::{ExposeSecret as _, SecretString};

use super::{Fixture, TestResult};

#[test]
fn a_password_record_sealed_by_the_key_with_the_router_id_opens() -> TestResult {
    let fixture = Fixture::new()?;
    let key = MasterKey::generate()?;
    let credentials = CredentialStore::new(fixture.state, key.duplicate());
    let password = SecretString::from(["existing", "-record"].concat());
    let record = serde_json::json!({ "schema": 1_u32, "sealed": key.seal("home", &password)? });
    let path = credentials.sealed_path("home", CredentialKind::Password)?;
    fs::write(&path, serde_json::to_vec_pretty(&record)?)?;

    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some("home.sealed")
    );
    assert_eq!(
        credentials
            .open("home", CredentialKind::Password)?
            .expose_secret(),
        password.expose_secret()
    );
    Ok(())
}

#[test]
fn each_kind_is_its_own_record_bound_to_its_kind() -> TestResult {
    let fixture = Fixture::new()?;
    let store = &fixture.credentials;
    for kind in CredentialKind::ALL {
        store.store(
            "home",
            kind,
            &SecretString::from(format!("secret-{}", kind.audit_name())),
        )?;
    }

    for kind in CredentialKind::ALL {
        assert_eq!(
            store.open("home", kind)?.expose_secret(),
            format!("secret-{}", kind.audit_name())
        );
    }
    let names = [
        store.sealed_path("home", CredentialKind::Token)?,
        store.sealed_path("home", CredentialKind::ReadPassword)?,
    ];
    assert_eq!(
        names.map(|path| path.file_name().map(ToOwned::to_owned)),
        [
            Some("home.token.sealed".into()),
            Some("home.read.sealed".into())
        ]
    );
    let _: u64 = fs::copy(
        store.sealed_path("home", CredentialKind::Token)?,
        store.sealed_path("home", CredentialKind::Password)?,
    )?;
    assert!(matches!(
        store.open("home", CredentialKind::Password),
        Err(CredentialError::Crypto(_))
    ));
    Ok(())
}

#[test]
fn remove_kind_removes_one_record_and_remove_every_record() -> TestResult {
    let fixture = Fixture::new()?;
    let store = &fixture.credentials;
    for kind in CredentialKind::ALL {
        store.store("home", kind, &SecretString::from("fixture"))?;
    }

    store.remove_kind("home", CredentialKind::ReadPassword)?;

    assert!(!store.exists("home", CredentialKind::ReadPassword)?);
    assert!(store.exists("home", CredentialKind::Password)?);
    assert!(store.exists("home", CredentialKind::Token)?);
    store.remove("home")?;
    for kind in CredentialKind::ALL {
        assert!(!store.exists("home", kind)?, "{kind:?}");
    }
    Ok(())
}

#[test]
fn manages_answers_per_kind() -> TestResult {
    let fixture = Fixture::new()?;
    let store = &fixture.credentials;
    let token = store.sealed_path("home", CredentialKind::Token)?;
    let legacy = store.legacy_path("home")?;

    assert!(store.manages("home", CredentialKind::Token, &token)?);
    assert!(!store.manages("home", CredentialKind::Password, &token)?);
    assert!(store.manages("home", CredentialKind::Password, &legacy)?);
    assert!(!store.manages("home", CredentialKind::ReadPassword, &legacy)?);
    Ok(())
}
