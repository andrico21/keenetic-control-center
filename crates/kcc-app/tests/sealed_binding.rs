//! Every sealed value is bound to its record type and owner: a router credential and an
//! account password hash never open as each other, and values sealed by an earlier
//! build are refused.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests assert sealed storage behaviour"
)]

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};
use std::{fs, path::Path};

use argon2::{Algorithm, Argon2, Version, password_hash::PasswordHasher as _};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit as _, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Generate as _, Payload},
};
use kcc_app::{
    accounts::{AccountError, AccountStore, Clock, NewAccount, SystemClock, password_params},
    credentials::{CredentialError, CredentialKind, CredentialStore},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::{CryptoError, MasterKey},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

/// Account and credential stores over one state directory and one master key, whose
/// bytes the test keeps to seal values the way an earlier build did.
struct World {
    /// Keeps the state directory alive.
    _temp: TempDir,
    /// The state root.
    state: StateStore,
    /// The master key's bytes.
    key: [u8; 32],
    /// UI accounts.
    accounts: AccountStore,
    /// Router credentials.
    credentials: CredentialStore,
}

impl World {
    fn new() -> Result<Self, Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        let key = <[u8; 32]>::try_generate().map_err(|error| error.to_string())?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        let accounts = AccountStore::new(
            state.clone(),
            MasterKey::from_bytes(key),
            Duration::from_secs(60),
            clock,
        );
        let credentials = CredentialStore::new(state.clone(), MasterKey::from_bytes(key));
        Ok(Self {
            _temp: temp,
            state,
            key,
            accounts,
            credentials,
        })
    }

    /// Creates the account `home` with `password`.
    fn create_home(&self, password: &SecretString) -> TestResult {
        self.accounts.create(
            &Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
            NewAccount::new("home".to_owned(), password.clone(), "admin".to_owned()),
        )?;
        Ok(())
    }

    /// The sealed password hash of the only account.
    fn account_hash(&self) -> Result<Value, Box<dyn Error>> {
        let users = read_json(&self.state.dir().join("users.json"))?;
        Ok(users
            .pointer("/users/0/password_hash")
            .cloned()
            .ok_or("password hash missing")?)
    }

    /// Replaces the sealed password hash of the only account.
    fn set_account_hash(&self, sealed: Value) -> TestResult {
        let path = self.state.dir().join("users.json");
        let mut users = read_json(&path)?;
        *users
            .pointer_mut("/users/0/password_hash")
            .ok_or("password hash missing")? = sealed;
        fs::write(&path, serde_json::to_vec(&users)?)?;
        Ok(())
    }

    /// `plaintext` sealed under the master key with `aad` as associated data, in the
    /// stored shape, the way a build with other associated data sealed it.
    fn seal_raw(&self, aad: &str, plaintext: &str) -> Result<Value, Box<dyn Error>> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.key).map_err(|error| error.to_string())?;
        let nonce = XNonce::try_generate().map_err(|error| error.to_string())?;
        let payload = Payload {
            msg: plaintext.as_bytes(),
            aad: aad.as_bytes(),
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|error| error.to_string())?;
        Ok(json!({
            "alg": "xchacha20poly1305",
            "nonce": STANDARD.encode(nonce.as_slice()),
            "ciphertext": STANDARD.encode(ciphertext),
        }))
    }
}

fn read_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

/// A password built at run time.
fn secret(label: &str) -> SecretString {
    SecretString::from([label, "sealed", "binding", "passphrase"].join("-"))
}

/// SEC2-18: a router credential record of any kind, moved into an account, does not
/// open as its password hash.
#[test]
fn a_router_credential_does_not_open_as_an_account_hash() -> TestResult {
    let world = World::new()?;
    world.create_home(&secret("account"))?;
    for kind in CredentialKind::ALL {
        world
            .credentials
            .store("home", kind, &secret(kind.audit_name()))?;
        let record = read_json(&world.credentials.sealed_path("home", kind)?)?;
        world.set_account_hash(record.get("sealed").cloned().ok_or("sealed missing")?)?;

        assert_eq!(world.accounts.fingerprint("home")?, None, "{kind:?}");
        assert!(
            matches!(
                world
                    .accounts
                    .authenticate("home", &secret(kind.audit_name())),
                Err(AccountError::Crypto(CryptoError::Decrypt))
            ),
            "{kind:?}"
        );
    }
    Ok(())
}

/// SEC2-18: an account's sealed password hash, moved into a router credential record,
/// does not open as any kind of credential.
#[test]
fn an_account_hash_does_not_open_as_a_router_credential() -> TestResult {
    let world = World::new()?;
    world.create_home(&secret("account"))?;
    world
        .credentials
        .store("home", CredentialKind::Password, &secret("router"))?;
    let mut record = read_json(
        &world
            .credentials
            .sealed_path("home", CredentialKind::Password)?,
    )?;
    *record.get_mut("sealed").ok_or("sealed missing")? = world.account_hash()?;

    for kind in CredentialKind::ALL {
        fs::write(
            world.credentials.sealed_path("home", kind)?,
            serde_json::to_vec(&record)?,
        )?;
        assert!(
            matches!(
                world.credentials.open("home", kind),
                Err(CredentialError::Crypto(_))
            ),
            "{kind:?}"
        );
    }
    Ok(())
}

/// SEC2-18: a credential record of the schema earlier builds wrote is refused as an
/// unsupported record, whatever associated data it was sealed under.
#[test]
fn a_credential_record_of_an_earlier_build_is_refused() -> TestResult {
    let world = World::new()?;
    let path = world
        .credentials
        .sealed_path("home", CredentialKind::Password)?;
    fs::create_dir_all(path.parent().ok_or("record path has no parent")?)?;
    for aad in ["home", "router:home"] {
        let record = json!({
            "schema": 1_u32,
            "sealed": world.seal_raw(aad, secret("router").expose_secret())?,
        });
        fs::write(&path, serde_json::to_vec_pretty(&record)?)?;

        assert!(
            matches!(
                world.credentials.open("home", CredentialKind::Password),
                Err(CredentialError::Record)
            ),
            "{aad}"
        );
    }
    Ok(())
}

/// SEC2-18: a password hash sealed by an earlier build does not open at sign-in.
///
/// Bound to the bare username, it is an error instead of a sign-in answer, and the
/// account has no fingerprint for a session to match.
#[test]
fn an_account_hash_of_an_earlier_build_is_an_error_at_sign_in() -> TestResult {
    let world = World::new()?;
    let password = secret("account");
    world.create_home(&password)?;
    let params = password_params().map_err(|error| error.to_string())?;
    let phc = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.expose_secret().as_bytes())
        .map_err(|error| error.to_string())?
        .to_string();
    world.set_account_hash(world.seal_raw("home", &phc)?)?;

    assert!(matches!(
        world.accounts.authenticate("home", &password),
        Err(AccountError::Crypto(CryptoError::Decrypt))
    ));
    assert_eq!(world.accounts.fingerprint("home")?, None);
    Ok(())
}
