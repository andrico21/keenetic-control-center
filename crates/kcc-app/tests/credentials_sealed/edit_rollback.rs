//! A router edit seals its secrets as one change with the profile update: a refused or
//! failed update leaves every sealed record as it was.

use core::error::Error;
use std::{fs, process};

use kcc_app::{
    credentials::CredentialKind,
    permissions::built_in_roles,
    registry::{
        ManagedRouterProfile, RegistryError, RouterRegistry,
        sealed_edit::{SealedEdit, update_sealed},
    },
    settings::OutboundConfig,
};
use secrecy::{ExposeSecret as _, SecretString};
use url::Url;

use super::{Fixture, TestResult};

/// The bytes of every sealed record kind of `home` (`None` when absent).
fn records(fixture: &Fixture) -> Result<Vec<Option<Vec<u8>>>, Box<dyn Error>> {
    CredentialKind::ALL
        .into_iter()
        .map(|kind| {
            let path = fixture.credentials.sealed_path("home", kind)?;
            Ok(path.exists().then(|| fs::read(&path)).transpose()?)
        })
        .collect()
}

/// A secret built at run time.
fn secret(label: &str) -> SecretString {
    SecretString::from([label, "-", &process::id().to_string()].concat())
}

/// SEC1-09, W1-05, F-02, N17: an edit seals only with a stored profile.
///
/// An invalid profile seals nothing, a failed state write restores every sealed record
/// byte for byte (a kind that had none has none again), and a successful update keeps
/// the new records.
#[tokio::test]
async fn an_edit_seals_only_with_a_stored_profile() -> TestResult {
    let fixture = Fixture::new()?;
    let registry = RouterRegistry::new(fixture.state.clone(), &[], &OutboundConfig::default())?;
    let admin = built_in_roles()
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or("admin role missing")?;
    let mut profile = ManagedRouterProfile::new(
        "home".to_owned(),
        Url::parse("http://127.0.0.1:9")?,
        "admin".to_owned(),
        fixture
            .credentials
            .sealed_path("home", CredentialKind::Password)?,
    );
    profile.read_login = Some("reader".to_owned());
    profile.read_password_file = Some(
        fixture
            .credentials
            .sealed_path("home", CredentialKind::ReadPassword)?,
    );
    registry.create(&admin, profile.clone()).await?;
    let old = secret("old");
    for kind in [CredentialKind::Password, CredentialKind::ReadPassword] {
        fixture.credentials.store("home", kind, &old)?;
    }
    let before = records(&fixture)?;
    let new = [
        (CredentialKind::Password, secret("new")),
        (CredentialKind::Token, secret("token")),
        (CredentialKind::ReadPassword, secret("reader")),
    ];
    let mut moved = profile.clone();
    moved.url = Url::parse("http://127.0.0.1:10/ui")?;

    let invalid = update_sealed(
        &registry,
        &fixture.credentials,
        &admin,
        SealedEdit::new(moved, &new),
    )
    .await;

    assert!(matches!(
        invalid,
        Err(RegistryError::InvalidProfile { reason: _ })
    ));
    assert_eq!(
        records(&fixture)?,
        before,
        "an invalid profile seals nothing"
    );
    let blocker = fixture.state.dir().join(".routers.json.tmp");
    fs::create_dir_all(blocker.join("held"))?;

    let failed = update_sealed(
        &registry,
        &fixture.credentials,
        &admin,
        SealedEdit::new(profile.clone(), &new),
    )
    .await;

    assert!(matches!(failed, Err(RegistryError::State(_))), "{failed:?}");
    assert_eq!(records(&fixture)?, before, "every record restored");
    fs::remove_dir_all(&blocker)?;

    update_sealed(
        &registry,
        &fixture.credentials,
        &admin,
        SealedEdit::new(profile, &new),
    )
    .await?;

    for (kind, value) in &new {
        assert_eq!(
            fixture.credentials.open("home", *kind)?.expose_secret(),
            value.expose_secret()
        );
    }
    Ok(())
}
