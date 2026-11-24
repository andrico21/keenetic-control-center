//! In-process OIDC identity provider for resource-server tests: a JWKS over TLS and the
//! tokens it signs.
//!
//! [`FakeIdp`] serves `GET /jwks` on `https://localhost:<port>/jwks` and nothing else,
//! with a certificate for `localhost` from its own CA ([`FakeIdp::ca_pem`]). Its keys are
//! one ES256 (P-256) and one Ed25519 key, signed with `ring`; there is no RSA anywhere.
//! [`FakeIdp::token`] issues a token for [`tokens::Claims`], [`FakeIdp::forged`] builds the
//! tokens a resource server must refuse, [`FakeIdp::rotate`] replaces both keys and
//! [`FakeIdp::set_mode`] makes the JWKS unreachable or slow.

use alloc::sync::Arc;
use core::{error::Error, future::pending, net::SocketAddr};
use std::{
    io,
    sync::{Mutex, MutexGuard, PoisonError},
};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::{
    ServerConfig,
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;

use self::tokens::{Algorithm, Claims, Forgery, KeySet};

pub mod tokens;

/// How the JWKS endpoint answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Mode {
    /// Serves the keys.
    Serving,
    /// Closes every connection at once, before TLS: an unreachable provider.
    Refusing,
    /// Accepts connections and never answers: a slow provider.
    Stalling,
}

/// What the connections read.
#[derive(Debug)]
struct State {
    /// The served keys.
    keys: KeySet,
    /// How the endpoint answers.
    mode: Mode,
    /// How many JWKS documents were sent.
    fetches: u64,
}

/// A running fake identity provider; stopped on drop.
#[derive(Debug)]
pub struct FakeIdp {
    /// Where it listens.
    address: SocketAddr,
    /// Its CA certificate, PEM.
    ca_pem: String,
    /// The keys and the mode.
    state: Arc<Mutex<State>>,
    /// The accept loop; it owns every connection.
    task: JoinHandle<()>,
}

impl Drop for FakeIdp {
    #[inline]
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeIdp {
    /// Starts the provider on `127.0.0.1` with a fresh CA, a `localhost` certificate and
    /// fresh keys, serving.
    ///
    /// # Errors
    ///
    /// The key or certificate generation, the TLS setup or the bind failed.
    // cancel-safe: binds a listener and spawns its loop; nothing is shared before return.
    #[inline]
    pub async fn spawn() -> io::Result<Self> {
        let (ca_pem, tls) = tls_identity().map_err(io::Error::other)?;
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let address = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State {
            keys: KeySet::generate()?,
            mode: Mode::Serving,
            fetches: 0,
        }));
        let task = tokio::spawn(accepting(
            listener,
            TlsAcceptor::from(Arc::new(tls)),
            Arc::clone(&state),
        ));
        Ok(Self {
            address,
            ca_pem,
            state,
            task,
        })
    }

    /// The CA that issued the provider's TLS certificate, PEM.
    #[inline]
    #[must_use]
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// The JWKS URL: `https://localhost:<port>/jwks`.
    #[inline]
    #[must_use]
    pub fn jwks_uri(&self) -> String {
        format!("https://localhost:{}/jwks", self.address.port())
    }

    /// The bound address.
    #[inline]
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Sets how the JWKS endpoint answers new connections.
    #[inline]
    pub fn set_mode(&self, mode: Mode) {
        self.locked().mode = mode;
    }

    /// How many JWKS documents were sent so far.
    #[inline]
    #[must_use]
    pub fn fetches(&self) -> u64 {
        self.locked().fetches
    }

    /// Replaces both keys with new ones under new key ids; the JWKS serves only them.
    ///
    /// # Errors
    ///
    /// The key generation failed.
    #[inline]
    pub fn rotate(&self) -> io::Result<()> {
        let keys = KeySet::generate()?;
        self.locked().keys = keys;
        Ok(())
    }

    /// A token for `claims` signed with the served ES256 key.
    ///
    /// # Errors
    ///
    /// The signature failed.
    #[inline]
    pub fn token(&self, claims: &Claims) -> io::Result<String> {
        self.token_with(Algorithm::Es256, claims)
    }

    /// A token for `claims` signed with the served key of `algorithm`.
    ///
    /// # Errors
    ///
    /// The signature failed.
    #[inline]
    pub fn token_with(&self, algorithm: Algorithm, claims: &Claims) -> io::Result<String> {
        self.locked().keys.sign(algorithm, claims)
    }

    /// A token for `claims` a resource server must refuse, built as `forgery` says.
    ///
    /// # Errors
    ///
    /// A key or a signature failed.
    #[inline]
    pub fn forged(&self, forgery: Forgery, claims: &Claims) -> io::Result<String> {
        self.locked().keys.forge(forgery, claims)
    }

    /// The state, poisoned or not.
    fn locked(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A fresh CA and the TLS server configuration of a `localhost` certificate it signed.
///
/// # Errors
///
/// The generation or the TLS setup failed.
fn tls_identity() -> Result<(String, ServerConfig), Box<dyn Error + Send + Sync>> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "kcc fake identity provider CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate()?;
    let leaf =
        CertificateParams::new(vec!["localhost".to_owned()])?.signed_by(&leaf_key, &issuer)?;
    let chain = vec![leaf.der().clone(), CertificateDer::from(ca.der().to_vec())];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok((ca.pem(), config))
}

/// Accepts connections until aborted; dropping it drops every connection.
// cancel-safe: aborting drops the listener and the connections it owns.
async fn accepting(listener: TcpListener, acceptor: TlsAcceptor, state: Arc<Mutex<State>>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { continue };
                let mode = state.lock().unwrap_or_else(PoisonError::into_inner).mode;
                match mode {
                    Mode::Refusing => drop(stream),
                    Mode::Stalling => drop(connections.spawn(stalled(stream))),
                    Mode::Serving => {
                        drop(connections.spawn(answer(stream, acceptor.clone(), Arc::clone(&state))));
                    }
                }
            }
            Some(_done) = connections.join_next() => {}
        }
    }
}

/// Holds `stream` open without answering until the provider stops.
// cancel-safe: holds a socket only.
async fn stalled(stream: TcpStream) {
    let _held = stream;
    pending::<()>().await;
}

/// Answers one HTTPS request on `stream`: the JWKS for `GET /jwks`, 404 otherwise.
// cancel-safe: one connection; dropping it closes the connection.
async fn answer(stream: TcpStream, acceptor: TlsAcceptor, state: Arc<Mutex<State>>) {
    let Ok(mut tls) = acceptor.accept(stream).await else {
        return;
    };
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") && head.len() < 16 * 1024 {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(read) => head.extend_from_slice(chunk.get(..read).unwrap_or_default()),
        }
    }
    let jwks = head.starts_with(b"GET /jwks ");
    let (status, body) = if jwks {
        let mut locked = state.lock().unwrap_or_else(PoisonError::into_inner);
        locked.fetches = locked.fetches.saturating_add(1);
        let document: Value = locked.keys.jwks();
        drop(locked);
        ("200 OK", document.to_string())
    } else {
        ("404 Not Found", "{}".to_owned())
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    if tls.write_all(reply.as_bytes()).await.is_ok() {
        drop(tls.shutdown().await);
    }
}
