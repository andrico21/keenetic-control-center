//! Router registry reload integration tests.
#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration-test assertions and fixture filesystem setup"
)]

extern crate alloc;

use core::error::Error;

use kcc_app::{
    persist::StateStore,
    registry::{ManagedRouterProfile, RegistryError, RouterRegistry},
    settings::{Config, OutboundConfig, RouterTls},
};
use tempfile::TempDir;

#[path = "registry/auth_modes.rs"]
mod auth_modes;
#[cfg(unix)]
#[path = "registry/client_pool.rs"]
mod client_pool;
#[path = "registry/inflight.rs"]
mod inflight;
#[cfg(unix)]
#[path = "registry/secret_files.rs"]
mod secret_files;

#[tokio::test]
async fn reload_replaces_changed_config_profile() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let password = kcc_testkit::write_secret_file(directory.path(), "password", "fixture")?;
    let initial = config(&password, 18080)?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let registry = RouterRegistry::new(state, &initial.routers, &OutboundConfig::default())?;
    let replacement = config(&password, 18081)?;

    let invalidated = registry.reload(&replacement).await?;

    assert_eq!(invalidated, 1);
    assert_eq!(registry.get("router")?.profile.url.port(), Some(18081));
    Ok(())
}

/// B-13: the registry refuses a malformed TLS pin when a profile is stored, as `kcc.toml`
/// validation does, instead of only when a client is built.
#[test]
fn registry_profile_with_a_malformed_tls_pin_is_invalid() -> Result<(), Box<dyn Error>> {
    let mut profile = ManagedRouterProfile::new(
        "home".to_owned(),
        url::Url::parse("http://203.0.113.10")?,
        "admin".to_owned(),
        "/etc/kcc/home.pw".into(),
    );
    profile.tls = RouterTls::PinSha256("abc".to_owned());

    let checked = profile.validate();

    assert!(
        matches!(checked, Err(RegistryError::InvalidProfile { reason: _ })),
        "{checked:?}"
    );
    Ok(())
}

fn config(password: &std::path::Path, port: u16) -> Result<Config, Box<dyn Error>> {
    Ok(Config::from_toml_str(&format!(
        "[[routers]]\nname = \"router\"\nurl = \"http://127.0.0.1:{port}\"\nlogin = \"admin\"\npassword_file = {:?}\n",
        password.display().to_string()
    ))?)
}
