//! One sealed record per credential kind, each bound to its router and kind; password
//! records keep their original file name.

use std::{ffi::OsStr, fs};

use kcc_app::credentials::{CredentialError, CredentialKind};
use secrecy::{ExposeSecret as _, SecretString};

use super::{Fixture, TestResult};

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
    let names = ["home.sealed", "home.token.sealed", "home.read.sealed"];
    for (kind, name) in CredentialKind::ALL.into_iter().zip(names) {
        assert_eq!(
            store.sealed_path("home", kind)?.file_name(),
            Some(OsStr::new(name))
        );
    }
    for from in CredentialKind::ALL {
        for to in CredentialKind::ALL.into_iter().filter(|&to| to != from) {
            let _: u64 = fs::copy(
                store.sealed_path("home", from)?,
                store.sealed_path("home", to)?,
            )?;
            assert!(
                matches!(store.open("home", to), Err(CredentialError::Crypto(_))),
                "{from:?} as {to:?}"
            );
            store.store(
                "home",
                to,
                &SecretString::from(format!("secret-{}", to.audit_name())),
            )?;
        }
    }
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
