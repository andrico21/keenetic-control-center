//! A reconnect of a token profile keeps its token, stores no password, saves the new URL
//! and leaves the next client to log in with the stored token.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]

use core::{error::Error, net::SocketAddr};
use std::{fs, process};

use kcc_rci::auth::Credentials;
use kcc_testkit::{DEFAULT_LOGIN, FakeRouter, model::Profile};
use secrecy::{ExposeSecret as _, SecretString};
use tempfile::TempDir;
use url::Url;

use super::{Arc, ManagedRouterProfile, RegistryError, RouterRegistry};
use crate::{
    credentials::{CredentialKind, CredentialStore},
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
    settings::{Config, OutboundConfig, RouterAuth},
};

#[tokio::test]
async fn token_profile_reconnect_keeps_the_token_and_saves_the_url() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let password = format!("probe-{}", process::id());
    let (address, handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, &password, ["cli", "http-proxy"])
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let store = Arc::new(CredentialStore::new(
        state.clone(),
        MasterKey::from_bytes([5_u8; 32]),
    ));
    let outbound = OutboundConfig {
        allow_loopback: true,
        ..OutboundConfig::default()
    };
    let registry = RouterRegistry::new(state, &[], &outbound)?.with_credentials(Arc::clone(&store));
    let role = Role::new("admin".to_owned(), Permission::ALL, Vec::new());
    let url = Url::parse(&format!("http://{address}"))?;
    let probe_file = kcc_testkit::write_secret_file(directory.path(), "probe", &password)?;
    registry
        .create(
            &role,
            ManagedRouterProfile::new(
                "probe".to_owned(),
                url.clone(),
                DEFAULT_LOGIN.to_owned(),
                probe_file,
            ),
        )
        .await?;
    let token = SecretString::from(format!("token-{}", process::id()));
    store.store("home", CredentialKind::Token, &token)?;
    let mut profile = ManagedRouterProfile::new(
        "home".to_owned(),
        Url::parse("http://203.0.113.10")?,
        String::new(),
        store.sealed_path("home", CredentialKind::Password)?,
    );
    profile.password_file = None;
    profile.auth = RouterAuth::Token;
    profile.token_file = Some(store.sealed_path("home", CredentialKind::Token)?);
    registry.create(&role, profile).await?;
    let client = registry.client("probe").await?;
    let replacement = Credentials::new(DEFAULT_LOGIN.to_owned(), SecretString::from(password));

    registry
        .transition("home", client, Some(replacement))
        .await?;

    let reconnected = registry.get("home")?.profile;
    assert_eq!(reconnected.url, url);
    assert_eq!(reconnected.password_file, None);
    assert_eq!(
        store.open("home", CredentialKind::Token)?.expose_secret(),
        token.expose_secret()
    );
    assert!(!store.exists("home", CredentialKind::Password)?);
    assert!(!registry.clients.lock().await.contains_key("home"));
    handle.shutdown().await?;
    Ok(())
}

/// B-24: a `kcc.toml` router cannot be moved to another URL by a transition: the
/// transition is refused, names the router, and neither the URL nor the operator's
/// password file changes.
#[tokio::test]
async fn config_router_url_transition_is_refused_and_writes_nothing() -> Result<(), Box<dyn Error>>
{
    let directory = TempDir::new()?;
    let password = format!("probe-{}", process::id());
    let (address, handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, &password, ["cli", "http-proxy"])
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let old_password = format!("old-{}", process::id());
    let home_file = kcc_testkit::write_secret_file(directory.path(), "home", &old_password)?;
    let config = Config::from_toml_str(&format!(
        "[[routers]]\nname = \"home\"\nurl = \"http://203.0.113.10\"\nlogin = \"admin\"\npassword_file = {:?}\n",
        home_file.display().to_string()
    ))?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let outbound = OutboundConfig {
        allow_loopback: true,
        ..OutboundConfig::default()
    };
    let registry = RouterRegistry::new(state, &config.routers, &outbound)?;
    let role = Role::new("admin".to_owned(), Permission::ALL, Vec::new());
    let probe_file = kcc_testkit::write_secret_file(directory.path(), "probe", &password)?;
    registry
        .create(
            &role,
            ManagedRouterProfile::new(
                "probe".to_owned(),
                Url::parse(&format!("http://{address}"))?,
                DEFAULT_LOGIN.to_owned(),
                probe_file,
            ),
        )
        .await?;
    let client = registry.client("probe").await?;
    let replacement = Credentials::new(DEFAULT_LOGIN.to_owned(), SecretString::from(password));

    let refused = registry.transition("home", client, Some(replacement)).await;

    match refused {
        Err(RegistryError::ConfigRoute { id, url: _ }) => assert_eq!(id, "home"),
        other => return Err(format!("expected a config-route refusal, got {other:?}").into()),
    }
    assert_eq!(
        registry.get("home")?.profile.url,
        Url::parse("http://203.0.113.10")?
    );
    assert_eq!(fs::read_to_string(&home_file)?, old_password);
    handle.shutdown().await?;
    Ok(())
}
