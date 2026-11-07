//! Live source routers of the migration matrix, seeded and saved before planning.

use core::{error::Error, str::FromStr as _};
use std::io;

use kcc_app::registry::ManagedRouterProfile;
use kcc_rci::{
    ConfigKind, OutboundPolicy, RciClient, RciClientOptions, RouterUrl, SecretBytes,
    auth::Credentials,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, Handle, model::Profile};
use secrecy::SecretString;
use tempfile::TempDir;
use tokio::fs;
use url::Url;

use super::support::Fixture;

/// A seeded live source router.
pub(crate) struct LiveSource {
    /// Owner of the source password file.
    directory: TempDir,
    /// Server handle.
    handle: Handle,
    /// Source origin.
    url: RouterUrl,
}

impl LiveSource {
    /// Stops the source router.
    ///
    /// # Errors
    /// Returns the server shutdown failure.
    // NOT cancel-safe: stops a background server.
    pub(crate) async fn shutdown(self) -> io::Result<()> {
        self.handle.shutdown().await
    }
}

/// Starts a live source router, applies the seed and saves it to startup configuration.
///
/// # Errors
/// Returns fixture or parser failures, including a seed line the simulator rejects.
// NOT cancel-safe: mutates the isolated source router.
pub(crate) async fn seed_source(
    profile: Profile,
    lines: &[String],
) -> Result<LiveSource, Box<dyn Error>> {
    let (address, handle) = FakeRouter::builder(profile)
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let url = RouterUrl::from_str(&format!("http://{address}"))?;
    let client = RciClient::connect_with(
        url.clone(),
        Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        ),
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true)),
    )
    .await?;
    for line in lines
        .iter()
        .map(String::as_str)
        .chain(["system configuration save"])
    {
        drop(client.parse(line).await?);
    }
    Ok(LiveSource {
        directory: TempDir::new()?,
        handle,
        url,
    })
}

/// Registers the live source and downloads its saved configuration through the registry.
///
/// # Errors
/// Returns registry or transport failures.
// NOT cancel-safe: writes a temporary password file and registry state.
pub(crate) async fn register_source(
    fixture: &Fixture,
    source: &LiveSource,
) -> Result<SecretBytes, Box<dyn Error>> {
    let password_file = source.directory.path().join("password");
    fs::write(&password_file, DEFAULT_PASSWORD).await?;
    fixture
        .registry
        .create(
            &fixture.role,
            ManagedRouterProfile::new(
                "source".to_owned(),
                Url::parse(source.url.as_str())?,
                DEFAULT_LOGIN.to_owned(),
                password_file,
            ),
        )
        .await?;
    Ok(fixture
        .registry
        .client("source")
        .await?
        .download_config(ConfigKind::Startup)
        .await?)
}
