//! Config-file routers authenticate with the scheme their `auth` key selects, and stored
//! profiles keep their on-disk form.

use core::{error::Error, net::SocketAddr, sync::atomic::Ordering};
use std::{fs, path::Path};

use kcc_app::{
    persist::StateStore,
    registry::{RegistryError, RouterRegistry, RoutersDocument},
    settings::{Config, OutboundConfig},
};
use kcc_rci::RciPath;
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD,
    auth_fixture::{self, Counts, Options as Fixture, Protocol},
};
use tempfile::TempDir;

/// A `routers.json` exactly as the registry wrote it before profiles carried an auth mode.
const STORED_ROUTERS: &str = r#"{
  "routers": [
    {
      "id": "lab",
      "login": "admin",
      "password_file": "/var/lib/kcc/credentials/lab.sealed",
      "read_login": null,
      "read_password_file": null,
      "tags": [],
      "test_device": false,
      "tls": "verify",
      "url": "http://203.0.113.10/"
    },
    {
      "id": "office",
      "login": "admin",
      "password_file": "/etc/kcc/office.pw",
      "read_login": "monitor",
      "read_password_file": "/etc/kcc/office-read.pw",
      "tags": [
        "branch"
      ],
      "test_device": true,
      "tls": {
        "pin_sha256": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
      },
      "url": "https://198.51.100.7/"
    }
  ],
  "schema": 1
}
"#;

/// Builds a registry holding one config-defined router whose entry ends with `auth_lines`.
fn registry(
    directory: &Path,
    address: SocketAddr,
    auth_lines: &str,
) -> Result<RouterRegistry, Box<dyn Error>> {
    let config = Config::from_toml_str(&format!(
        "[outbound]\nallow_loopback = true\n\n[[routers]]\nname = \"router\"\nurl = \"http://{address}\"\n{auth_lines}"
    ))?;
    Ok(RouterRegistry::new(
        StateStore::open(&directory.join("state"))?,
        &config.routers,
        &config.outbound,
    )?)
}

/// Writes the fixture password and returns the `[[routers]]` lines of a password profile.
fn password_lines(directory: &Path, auth: &str) -> Result<String, Box<dyn Error>> {
    let path = directory.join("password");
    fs::write(&path, DEFAULT_PASSWORD)?;
    Ok(format!(
        "login = \"{DEFAULT_LOGIN}\"\npassword_file = {:?}\nauth = \"{auth}\"\n",
        path.display().to_string()
    ))
}

/// Sends one read through the registry's shared client for the config router.
// NOT cancel-safe: the first request may run a login exchange against the fixture.
async fn read_once(registry: &RouterRegistry) -> Result<(), Box<dyn Error>> {
    let path = RciPath::from_segments(["show", "version"])?;
    drop(registry.client("router").await?.get(&path, &()).await?);
    Ok(())
}

/// Number of fixture requests counted by `counter`.
fn count(counts: &Counts, counter: fn(&Counts) -> &core::sync::atomic::AtomicUsize) -> usize {
    counter(counts).load(Ordering::SeqCst)
}

/// `auth = "token"` with `token_file` sends the token header and never logs in.
// NOT cancel-safe: owns the fixture through one resource request.
#[tokio::test]
async fn token_profile_sends_the_token_header() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let mut fixture = Fixture::default();
    fixture.protocol = Protocol::Token;
    let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
    let token = directory.path().join("token");
    fs::write(&token, format!("{}\n", ["fixture", "token"].join("-")))?;
    let lines = format!(
        "auth = \"token\"\ntoken_file = {:?}\n",
        token.display().to_string()
    );

    read_once(&registry(directory.path(), address, &lines)?).await?;

    assert_eq!(
        count(&counts, |seen| &seen.token_requests),
        1,
        "token requests"
    );
    assert_eq!(count(&counts, |seen| &seen.auth_get), 0, "auth probes");
    handle.shutdown().await?;
    Ok(())
}

/// `auth = "digest"` signs the request with HTTP Digest instead of a cookie login.
// NOT cancel-safe: owns the fixture through one resource request.
#[tokio::test]
async fn digest_profile_signs_with_digest() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let mut fixture = Fixture::default();
    fixture.protocol = Protocol::DigestSha256;
    let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
    let lines = password_lines(directory.path(), "digest")?;

    read_once(&registry(directory.path(), address, &lines)?).await?;

    assert_eq!(
        count(&counts, |seen| &seen.digest_requests),
        1,
        "digest requests"
    );
    assert_eq!(count(&counts, |seen| &seen.auth_get), 0, "auth probes");
    handle.shutdown().await?;
    Ok(())
}

/// `auth = "ndw2"` logs in with ndw2 although the router also advertises ndw4.
// NOT cancel-safe: owns the fixture through a login and one resource request.
#[tokio::test]
async fn ndw2_profile_skips_advertised_ndw4() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let (address, handle, counts) = auth_fixture::spawn(Fixture::default()).await?;
    let lines = password_lines(directory.path(), "ndw2")?;

    read_once(&registry(directory.path(), address, &lines)?).await?;

    assert_eq!(count(&counts, |seen| &seen.ndw2_posts), 1, "ndw2 logins");
    assert_eq!(count(&counts, |seen| &seen.phase_two), 0, "ndw4 phases");
    handle.shutdown().await?;
    Ok(())
}

/// A stored `routers.json` loads into the registry and is written back byte for byte.
#[test]
fn stored_routers_round_trip_byte_identical() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let state = directory.path().join("state");
    let store = StateStore::open(&state)?;
    fs::write(state.join("routers.json"), STORED_ROUTERS)?;
    let registry = RouterRegistry::new(store.clone(), &[], &OutboundConfig::default())?;
    assert_eq!(registry.list()?.len(), 2, "loaded profiles");

    store.update::<RoutersDocument, _, _>(|_document| ())?;

    assert_eq!(
        fs::read_to_string(state.join("routers.json"))?,
        STORED_ROUTERS
    );
    Ok(())
}

/// A stored token file under a password auth mode is refused, naming `token_file`.
#[test]
fn token_file_with_ndw4_names_the_field() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let state = directory.path().join("state");
    let store = StateStore::open(&state)?;
    let stored = STORED_ROUTERS.replace(
        "\"password_file\": \"/var/lib/kcc/credentials/lab.sealed\",",
        "\"auth\": \"ndw4\",\n      \"token_file\": \"/etc/kcc/lab.token\",",
    );
    fs::write(state.join("routers.json"), stored)?;

    let result = RouterRegistry::new(store, &[], &OutboundConfig::default());

    let reason = match result {
        Err(RegistryError::InvalidProfile { reason }) => reason,
        Err(other) => return Err(format!("unexpected error: {other}").into()),
        Ok(_registry) => return Err("token_file with auth = ndw4 was accepted".into()),
    };
    assert!(reason.starts_with("token_file"), "reason: {reason}");
    Ok(())
}
