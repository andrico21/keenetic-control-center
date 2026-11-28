//! Bounded Argon2 work and zeroizing SCRAM key storage.

use alloc::sync::Arc;
use core::fmt;
use std::sync::LazyLock;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use secrecy::ExposeSecret as _;
use sha3::{Digest as _, Sha3_512};
use tokio::{sync::Semaphore, task};
use zeroize::Zeroizing;

use crate::{AuthError, LocalCause, RciError, TransportCause, auth::Credentials};

/// Global budget for concurrent Argon2 derivations (default: one).
static BUDGET: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(1)));

/// The three SCRAM keys; no public debug representation exposes their bytes.
pub(crate) struct Keys {
    /// Client proof key.
    client: Zeroizing<[u8; 64]>,
    /// Hash of the client key.
    stored: Zeroizing<[u8; 64]>,
    /// Server authentication key.
    server: Zeroizing<[u8; 64]>,
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            client: _,
            stored: _,
            server: _,
        } = self;
        f.write_str("Keys([REDACTED])")
    }
}

/// Validated key derivation parameters. Router and login are bound by the owning manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Parameters {
    /// Decoded 16-byte salt.
    pub salt: [u8; 16],
    /// Iterations in 1..=64, at most the local cap.
    pub iterations: u32,
    /// Memory in 8..=262144 KiB, below the local cap.
    pub memory: u32,
}

impl Keys {
    /// Derives keys off the executor with the permit retained until blocking work ends.
    ///
    /// # Errors
    /// Returns an error if parameters, the runtime, or key derivation fail.
    // cancel-safe: detached blocking work owns its permit and zeroizing password until completion.
    pub(crate) async fn derive(
        credentials: &Credentials,
        parameters: Parameters,
    ) -> Result<Self, RciError> {
        let budget = Arc::clone(&*BUDGET);
        let permit = budget
            .acquire_owned()
            .await
            .map_err(|_closed| RciError::Transport(TransportCause::Local(LocalCause::Budget)))?;
        let password = credentials.password.clone();
        task::spawn_blocking(move || {
            let result = Self::derive_sync(password.expose_secret().as_bytes(), parameters);
            drop(permit);
            result
        })
        .await
        .map_err(|_join| RciError::Transport(TransportCause::Local(LocalCause::Worker)))?
    }

    /// Performs the Argon2id calculation and immediately erases the salted password.
    ///
    /// # Errors
    /// Returns rejection if the KDF parameters or HMAC initialization are invalid.
    fn derive_sync(password: &[u8], parameters: Parameters) -> Result<Self, RciError> {
        let salted = salted_password(password, parameters)?;
        let client = mac(&salted, b"NDW4 Interactive Client Key")?;
        let stored = Zeroizing::new(Sha3_512::digest(client.as_slice()).into());
        let server = mac(&salted, b"NDW4 Interactive Server Key")?;
        Ok(Self {
            client,
            stored,
            server,
        })
    }

    /// Signs an authentication message as a base64 client proof.
    ///
    /// # Errors
    /// Returns rejection if HMAC initialization fails.
    pub(crate) fn proof(&self, message: &str) -> Result<Zeroizing<String>, RciError> {
        let mut signature = mac(&self.stored, message.as_bytes())?;
        for (byte, key) in signature.iter_mut().zip(self.client.iter()) {
            *byte ^= key;
        }
        Ok(Zeroizing::new(STANDARD.encode(signature.as_slice())))
    }

    /// Computes the expected server signature.
    ///
    /// # Errors
    /// Returns rejection if HMAC initialization fails.
    pub(crate) fn signature(&self, message: &str) -> Result<Zeroizing<[u8; 64]>, RciError> {
        mac(&self.server, message.as_bytes())
    }
}

/// Computes the protocol's 64-byte Argon2id password material.
///
/// # Errors
/// Rejects invalid KDF parameters or password inputs.
fn salted_password(
    password: &[u8],
    parameters: Parameters,
) -> Result<Zeroizing<[u8; 64]>, RciError> {
    let params = Params::new(parameters.memory, parameters.iterations, 1, Some(64))
        .map_err(|_error| RciError::Auth(AuthError::Rejected))?;
    let mut salted = Zeroizing::new([0_u8; 64]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, &parameters.salt, salted.as_mut())
        .map_err(|_error| RciError::Auth(AuthError::Rejected))?;
    Ok(salted)
}

/// Computes HMAC-SHA3-512 into memory that erases on drop.
///
/// # Errors
/// Returns rejection if HMAC initialization fails.
fn mac(key: &[u8; 64], message: &[u8]) -> Result<Zeroizing<[u8; 64]>, RciError> {
    let mut hmac = SimpleHmac::<Sha3_512>::new_from_slice(key)
        .map_err(|_error| RciError::Auth(AuthError::Rejected))?;
    hmac.update(message);
    Ok(Zeroizing::new(hmac.finalize().into_bytes().into()))
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, time::Duration};

    use base64::Engine as _;
    use kcc_testkit::auth_fixture::{self, Options as Fixture};
    use secrecy::SecretString;
    use serde_json::Value;
    use tokio::{sync::Mutex, time::timeout};

    use super::{Arc, BUDGET, Credentials, Keys, Parameters, STANDARD, salted_password};
    use crate::{
        AuthError, OutboundPolicy, RciError, RouterUrl, TlsMode,
        auth_options::Options,
        session::{HttpTimeouts, Manager},
    };

    /// A loopback session manager for `router` with the authentication policy `options`.
    // NOT cancel-safe: cancellation can abandon synchronous DNS resolution, but sends no request.
    async fn loopback_manager(
        router: RouterUrl,
        credentials: Credentials,
        options: Options,
    ) -> Result<Manager, RciError> {
        let builder = OutboundPolicy::default()
            .with_loopback(true)
            .client_builder(&router, &TlsMode::Verify, HttpTimeouts::default())
            .await?;
        Manager::with_options_and_client_builder(router, Some(credentials), options, builder)
    }

    /// Fallible unit-test result.
    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    /// Serializes the tests that hold every Argon2 permit.
    static TURN: Mutex<()> = Mutex::const_new(());

    /// Reproduces every cryptographic intermediate from pinned TypeScript/hash-wasm output.
    #[test]
    fn reference_vector_matches_every_intermediate() -> TestResult {
        let vector: Value = serde_json::from_str(include_str!("../tests/vectors/ndw4.json"))?;
        let text = |name| {
            vector
                .get(name)
                .and_then(Value::as_str)
                .ok_or("missing vector field")
        };
        let parameters = Parameters {
            salt: STANDARD
                .decode(text("salt")?)?
                .try_into()
                .map_err(|_bytes| "invalid salt")?,
            iterations: text("iter")?.parse()?,
            memory: text("memcost")?.parse()?,
        };
        let salted = salted_password(text("password")?.as_bytes(), parameters)?;
        let keys = Keys::derive_sync(text("password")?.as_bytes(), parameters)?;
        for (name, bytes) in [
            ("salted", salted.as_slice()),
            ("client", keys.client.as_slice()),
            ("stored", keys.stored.as_slice()),
            ("server", keys.server.as_slice()),
        ] {
            assert_eq!(
                STANDARD.encode(bytes),
                text(name)?,
                "reference intermediate {name}"
            );
        }
        let message = text("message")?;
        assert_eq!(keys.proof(message)?.as_str(), text("proof")?);
        assert_eq!(
            STANDARD.encode(keys.signature(message)?.as_slice()),
            text("signature")?
        );
        assert_eq!(
            keys.proof(&format!("{message};signature4={}", text("signature")?))?
                .as_str(),
            text("signatureProof")?
        );
        Ok(())
    }

    /// Cached re-logins and local cost refusals complete even when all KDF permits are held.
    // NOT cancel-safe: owns two fixtures and a process-wide permit through the test.
    #[tokio::test]
    async fn cached_login_and_cost_rejection_never_enter_argon2_queue() -> TestResult {
        let _turn = TURN.lock().await;
        let (address, handle, _counts) = auth_fixture::spawn(Fixture::default()).await?;
        let credentials = Credentials::new("admin".to_owned(), SecretString::from("admin"));
        let manager = loopback_manager(
            format!("http://{address}").parse()?,
            credentials.clone(),
            Options::default(),
        )
        .await?;
        manager.ensure_session().await?;
        manager.logout().await;
        let budget = Arc::clone(&*BUDGET);
        let permit = budget.acquire_owned().await?;

        timeout(Duration::from_secs(2), manager.ensure_session()).await??;

        let (other_address, other_handle, _other_counts) =
            auth_fixture::spawn(Fixture::default()).await?;
        let Options {
            mode,
            experimental_token,
            token_fallback,
            max_argon2_memory_kib: _,
            max_argon2_iterations,
        } = Options::default();
        let options = Options {
            mode,
            experimental_token,
            token_fallback,
            max_argon2_memory_kib: 32,
            max_argon2_iterations,
        };
        let limited = loopback_manager(
            format!("http://{other_address}").parse()?,
            credentials,
            options,
        )
        .await?;
        let result = timeout(Duration::from_secs(2), limited.ensure_session()).await?;
        assert!(matches!(
            result,
            Err(RciError::Auth(AuthError::CostTooHigh))
        ));
        drop(permit);
        handle.shutdown().await?;
        other_handle.shutdown().await?;
        Ok(())
    }

    /// A-07: a background operation's dedicated session reuses the parent's keys, so its
    /// login completes while every Argon2 permit is held.
    // NOT cancel-safe: owns a fixture and a process-wide permit through the test.
    #[tokio::test]
    async fn background_session_reuses_the_parent_keys() -> TestResult {
        use core::sync::atomic::Ordering;

        let _turn = TURN.lock().await;
        let (address, handle, counts) = auth_fixture::spawn(Fixture::default()).await?;
        let router: RouterUrl = format!("http://{address}").parse()?;
        let credentials = Credentials::new("admin".to_owned(), SecretString::from("admin"));
        let options = crate::RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true));
        let client = crate::RciClient::connect_with(router, credentials, options).await?;
        let path = crate::RciPath::from_segments(["tools", "ping"])?;
        drop(client.get(&path, &()).await?);
        assert_eq!(counts.phase_three.load(Ordering::SeqCst), 1);
        let permit = Arc::clone(&*BUDGET).acquire_owned().await?;

        // The fixture answers an object without a process id or `continued`: a finished
        // command, started after its login.
        let started = timeout(
            Duration::from_secs(5),
            client.start(path, &serde_json::json!({})),
        )
        .await?;

        assert!(started.is_ok(), "{started:?}");
        assert_eq!(counts.phase_three.load(Ordering::SeqCst), 2);
        drop(permit);
        handle.shutdown().await?;
        Ok(())
    }
}
