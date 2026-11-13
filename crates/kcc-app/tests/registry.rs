//! Router registry reload integration tests.
#![expect(
    clippy::absolute_paths,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration-test assertions and fixture filesystem setup"
)]

use core::error::Error;
use std::fs;

use kcc_app::{
    persist::StateStore,
    registry::RouterRegistry,
    settings::{Config, OutboundConfig},
};
use tempfile::TempDir;

#[path = "registry/auth_modes.rs"]
mod auth_modes;
#[path = "registry/inflight.rs"]
mod inflight;

#[tokio::test]
async fn reload_replaces_changed_config_profile() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let password = directory.path().join("password");
    fs::write(&password, "fixture")?;
    let initial = config(&password, 18080)?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let registry = RouterRegistry::new(state, &initial.routers, &OutboundConfig::default())?;
    let replacement = config(&password, 18081)?;

    let invalidated = registry.reload(&replacement).await?;

    assert_eq!(invalidated, 1);
    assert_eq!(registry.get("router")?.profile.url.port(), Some(18081));
    Ok(())
}

fn config(password: &std::path::Path, port: u16) -> Result<Config, Box<dyn Error>> {
    Ok(Config::from_toml_str(&format!(
        "[[routers]]\nname = \"router\"\nurl = \"http://127.0.0.1:{port}\"\nlogin = \"admin\"\npassword_file = {:?}\n",
        password.display().to_string()
    ))?)
}
