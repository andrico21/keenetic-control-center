//! Router credential files that group or others can read are refused before login (unix).

use core::error::Error;
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path};

use kcc_app::{
    persist::StateStore,
    registry::{RegistryError, RouterRegistry},
    settings::Config,
};
use kcc_rci::RciPath;
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD,
    auth_fixture::{self, Options as Fixture},
};
use tempfile::TempDir;

/// A registry holding one config router whose password file has `mode`.
fn registry_with_password_mode(
    directory: &Path,
    address: core::net::SocketAddr,
    mode: u32,
) -> Result<(RouterRegistry, std::path::PathBuf), Box<dyn Error>> {
    let path = kcc_testkit::write_secret_file(directory, "password", DEFAULT_PASSWORD)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    let config = Config::from_toml_str(&format!(
        "[outbound]\nallow_loopback = true\n\n[[routers]]\nname = \"router\"\nurl = \"http://{address}\"\nlogin = \"{DEFAULT_LOGIN}\"\npassword_file = {:?}\n",
        path.display().to_string()
    ))?;
    let registry = RouterRegistry::new(
        StateStore::open(&directory.join("state"))?,
        &config.routers,
        &config.outbound,
    )?;
    Ok((registry, path))
}

/// A password file other users can read never reaches the router.
// NOT cancel-safe: owns the fixture through one connection attempt.
#[tokio::test]
async fn world_readable_password_file_is_refused_with_its_path() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let (address, handle, _counts) = auth_fixture::spawn(Fixture::default()).await?;
    let (registry, path) = registry_with_password_mode(directory.path(), address, 0o644)?;

    let refused = registry
        .client("router")
        .await
        .err()
        .ok_or("0644 accepted")?;

    assert!(
        matches!(&refused, RegistryError::CredentialPermissions { path: named } if *named == path),
        "{refused:?}"
    );
    handle.shutdown().await?;
    Ok(())
}

/// Owner-only password files (0600 and the 0400 of mounted secrets) authenticate.
// NOT cancel-safe: owns the fixture through one resource request per mode.
#[tokio::test]
async fn owner_only_password_files_authenticate() -> Result<(), Box<dyn Error>> {
    for mode in [0o600, 0o400] {
        let directory = TempDir::new()?;
        let (address, handle, _counts) = auth_fixture::spawn(Fixture::default()).await?;
        let (registry, _path) = registry_with_password_mode(directory.path(), address, mode)?;
        let show = RciPath::from_segments(["show", "version"])?;

        drop(registry.client("router").await?.get(&show, &()).await?);

        handle.shutdown().await?;
    }
    Ok(())
}
