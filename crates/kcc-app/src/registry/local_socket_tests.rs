//! The registry's local-socket hook reaches every client it builds.
#![cfg(unix)]
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]

use core::error::Error;
use std::net::TcpListener;

use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, model::Profile};
use tempfile::TempDir;
use url::Url;

use super::{ManagedRouterProfile, RouterRegistry};
use crate::{
    permissions::{Permission, Role},
    persist::StateStore,
    settings::OutboundConfig,
};

/// A registry built with the hook reaches a fake served only on its Unix socket: nothing
/// listens on the profile's TCP address.
// NOT cancel-safe: signs in to a fake router task it owns.
#[tokio::test]
async fn registry_clients_dial_the_registered_socket() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let (_relay, socket, handle) = FakeRouter::builder(Profile::default())
        .build()?
        .serve_local()?;
    let address = TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let outbound = OutboundConfig {
        allow_loopback: true,
        ..OutboundConfig::default()
    };
    let registry = RouterRegistry::new(
        StateStore::open(&directory.path().join("state"))?,
        &[],
        &outbound,
    )?
    .with_local_socket(address, socket);
    let role = Role::new("admin".to_owned(), Permission::ALL, Vec::new());
    let password = kcc_testkit::write_secret_file(directory.path(), "lab", DEFAULT_PASSWORD)?;
    registry
        .create(
            &role,
            ManagedRouterProfile::new(
                "lab".to_owned(),
                Url::parse(&format!("http://{address}"))?,
                kcc_testkit::DEFAULT_LOGIN.to_owned(),
                password,
            ),
        )
        .await?;

    let info = registry.client("lab").await?.detect().await?;

    assert!(info.hw_id().is_some());
    assert!(handle.request_count() > 0);
    handle.shutdown().await?;
    Ok(())
}
