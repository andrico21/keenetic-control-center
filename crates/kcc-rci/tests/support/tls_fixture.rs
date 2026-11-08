//! Shared self-signed TLS router fixture.

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, net::SocketAddr};

use axum::body::Body;
use hyper::{Request, body::Incoming, server::conn::http1::Builder, service::service_fn};
use hyper_util::rt::TokioIo;
use kcc_testkit::{FakeRouter, model::Profile};
use rustls::{crypto::ring::default_provider, pki_types::PrivatePkcs8KeyDer};
use sha2::{Digest as _, Sha256};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt as _;
use x509_parser::prelude::{FromDer as _, X509Certificate};

/// A TLS endpoint backed by the ordinary fake router.
pub(crate) struct TlsFixture {
    /// Listener address.
    address: SocketAddr,
    /// Leaf SPKI digest.
    fingerprint: [u8; 32],
    /// Listener and its child connections, aborted on drop.
    tasks: JoinSet<()>,
}

impl TlsFixture {
    /// Starts a self-signed fake router.
    // cancel-safe: dropping setup closes the listener; dropping the fixture aborts all tasks.
    pub(crate) async fn spawn() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let app = FakeRouter::builder(Profile::default()).build()?.router();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(["router.test".to_owned()])?;
        let certificate = cert.der().clone();
        let (_remaining, parsed) = X509Certificate::from_der(certificate.as_ref())?;
        let fingerprint = Sha256::digest(parsed.public_key().raw).into();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate],
                PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mut tasks = JoinSet::new();
        drop(tasks.spawn(async move {
            let mut connections = JoinSet::new();
            while let Ok((stream, _peer)) = listener.accept().await {
                let connection_acceptor = acceptor.clone();
                let connection_router = app.clone();
                drop(connections.spawn(async move {
                    let Ok(tls) = connection_acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let request_router = connection_router.clone();
                        async move { request_router.oneshot(request.map(Body::new)).await }
                    });
                    drop(
                        Builder::new()
                            .serve_connection(TokioIo::new(tls), service)
                            .await,
                    );
                }));
                while connections.try_join_next().is_some() {}
            }
        }));
        Ok(Self {
            address,
            fingerprint,
            tasks,
        })
    }

    /// Returns the listening socket.
    pub(crate) const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the expected SPKI digest.
    pub(crate) const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Stops the listener and every accepted connection.
    // cancel-safe: dropping the owned task set aborts the listener and its connections.
    pub(crate) async fn shutdown(mut self) {
        self.tasks.shutdown().await;
    }
}
