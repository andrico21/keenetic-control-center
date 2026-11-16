//! Sealed router credential storage and legacy-plaintext migration contracts.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use fallible filesystem fixtures and assertions"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::error::Error;
use std::fs;

use kcc_app::{
    credentials::{CredentialError, CredentialKind, CredentialStore, MigrationState},
    permissions::built_in_roles,
    persist::StateStore,
    registry::{ManagedRouterProfile, RegistryError, RouterRegistry},
    secrets::MasterKey,
    settings::OutboundConfig,
};
use secrecy::{ExposeSecret as _, SecretString};
use tempfile::TempDir;
use url::Url;

#[path = "credentials_sealed/edit_rollback.rs"]
mod edit_rollback;
#[path = "credentials_sealed/kinds.rs"]
mod kinds;

type TestResult = Result<(), Box<dyn Error>>;

struct Fixture {
    directory: TempDir,
    state: StateStore,
    credentials: CredentialStore,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let state = StateStore::open(&directory.path().join("state"))?;
        let credentials = CredentialStore::new(state.clone(), MasterKey::generate()?);
        Ok(Self {
            directory,
            state,
            credentials,
        })
    }
}

#[test]
fn store_round_trips_without_plaintext_and_binds_router_id() -> TestResult {
    let fixture = Fixture::new()?;
    let password = SecretString::from(["runtime", "-credential", "-alpha"].concat());

    fixture
        .credentials
        .store("router-a", CredentialKind::Password, &password)?;

    assert!(
        fixture
            .credentials
            .exists("router-a", CredentialKind::Password)?
    );
    assert_eq!(
        fixture
            .credentials
            .open("router-a", CredentialKind::Password)?
            .expose_secret(),
        password.expose_secret()
    );
    let bytes = fs::read(
        fixture
            .credentials
            .sealed_path("router-a", CredentialKind::Password)?,
    )?;
    assert!(
        !bytes
            .windows(password.expose_secret().len())
            .any(|part| { part == password.expose_secret().as_bytes() })
    );
    let _: u64 = fs::copy(
        fixture
            .credentials
            .sealed_path("router-a", CredentialKind::Password)?,
        fixture
            .credentials
            .sealed_path("router-b", CredentialKind::Password)?,
    )?;
    assert!(matches!(
        fixture
            .credentials
            .open("router-b", CredentialKind::Password),
        Err(CredentialError::Crypto(_))
    ));
    Ok(())
}

#[test]
fn wrong_key_and_tampered_record_return_typed_errors() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.credentials.store(
        "home",
        CredentialKind::Password,
        &SecretString::from("fixture-password"),
    )?;
    let wrong = CredentialStore::new(fixture.state.clone(), MasterKey::generate()?);

    assert!(matches!(
        wrong.open("home", CredentialKind::Password),
        Err(CredentialError::Crypto(_))
    ));
    let path = fixture
        .credentials
        .sealed_path("home", CredentialKind::Password)?;
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    let ciphertext = record
        .get_mut("sealed")
        .and_then(|sealed| sealed.get_mut("ciphertext"))
        .ok_or("sealed ciphertext missing")?;
    *ciphertext = serde_json::Value::String("tampered".to_owned());
    fs::write(&path, serde_json::to_vec(&record)?)?;
    assert!(matches!(
        fixture.credentials.open("home", CredentialKind::Password),
        Err(CredentialError::Crypto(_))
    ));
    Ok(())
}

#[test]
fn migration_seals_verifies_removes_and_is_idempotent() -> TestResult {
    let fixture = Fixture::new()?;
    let legacy = fixture.credentials.legacy_path("home")?;
    fs::create_dir_all(legacy.parent().ok_or("legacy path has no parent")?)?;
    fs::write(&legacy, "legacy-password\n")?;

    assert_eq!(
        fixture.credentials.migrate("home")?,
        MigrationState::Migrated
    );
    assert!(!legacy.exists());
    assert_eq!(
        fixture
            .credentials
            .open("home", CredentialKind::Password)?
            .expose_secret(),
        "legacy-password"
    );
    assert_eq!(
        fixture.credentials.migrate("home")?,
        MigrationState::Current
    );
    Ok(())
}

#[test]
fn migration_converges_when_sealed_and_plaintext_both_exist() -> TestResult {
    let fixture = Fixture::new()?;
    let legacy = fixture.credentials.legacy_path("home")?;
    fs::create_dir_all(legacy.parent().ok_or("legacy path has no parent")?)?;
    fs::write(&legacy, "same-password")?;
    fixture.credentials.store(
        "home",
        CredentialKind::Password,
        &SecretString::from("same-password"),
    )?;

    assert_eq!(
        fixture.credentials.migrate("home")?,
        MigrationState::Recovered
    );
    assert!(!legacy.exists());
    assert_eq!(
        fixture
            .credentials
            .open("home", CredentialKind::Password)?
            .expose_secret(),
        "same-password"
    );
    Ok(())
}

#[test]
fn migration_failure_leaves_plaintext_untouched() -> TestResult {
    let fixture = Fixture::new()?;
    let legacy = fixture.credentials.legacy_path("home")?;
    fs::create_dir_all(legacy.parent().ok_or("legacy path has no parent")?)?;
    fs::write(&legacy, "legacy-password")?;
    fixture.credentials.store(
        "home",
        CredentialKind::Password,
        &SecretString::from("different-password"),
    )?;

    assert!(matches!(
        fixture.credentials.migrate("home"),
        Err(CredentialError::MigrationConflict)
    ));
    assert_eq!(fs::read_to_string(&legacy)?, "legacy-password");
    Ok(())
}

#[test]
fn remove_is_idempotent() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.credentials.store(
        "home",
        CredentialKind::Password,
        &SecretString::from("fixture-password"),
    )?;

    fixture.credentials.remove("home")?;
    fixture.credentials.remove("home")?;

    assert!(
        !fixture
            .credentials
            .exists("home", CredentialKind::Password)?
    );
    Ok(())
}

#[tokio::test]
async fn registry_opens_managed_sealed_and_operator_password_files() -> TestResult {
    let fixture = Fixture::new()?;
    let credentials = Arc::new(fixture.credentials);
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let registry = RouterRegistry::new(fixture.state, &[], &outbound)?
        .with_credentials(Arc::clone(&credentials));
    credentials.store(
        "managed",
        CredentialKind::Password,
        &SecretString::from("managed-password"),
    )?;
    let managed = ManagedRouterProfile::new(
        "managed".to_owned(),
        Url::parse("http://127.0.0.1:9")?,
        "admin".to_owned(),
        credentials.legacy_path("managed")?,
    );
    let operator_path = kcc_testkit::write_secret_file(
        fixture.directory.path(),
        "operator.password",
        "operator-password",
    )?;
    let operator = ManagedRouterProfile::new(
        "operator".to_owned(),
        Url::parse("http://127.0.0.1:9")?,
        "admin".to_owned(),
        operator_path,
    );
    let admin = built_in_roles()
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or("admin role missing")?;
    registry.create(&admin, managed).await?;
    registry.create(&admin, operator).await?;

    assert!(matches!(
        registry
            .test_connection(&registry.get("managed")?.profile)
            .await,
        Err(RegistryError::Rci(_))
    ));
    assert!(matches!(
        registry
            .test_connection(&registry.get("operator")?.profile)
            .await,
        Err(RegistryError::Rci(_))
    ));
    Ok(())
}
