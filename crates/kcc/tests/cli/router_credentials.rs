//! Built-binary router credential storage and migration contracts.

use core::net::SocketAddr;
use std::{fs, path::Path};

use kcc_testkit::{DEFAULT_LOGIN, FakeRouter, model::Profile};

use super::support::{Env, TestResult};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_add_stores_only_sealed_bytes_and_authenticates() -> TestResult {
    let password = ["runtime", "-cli", "-password"].concat();
    let (address, _handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, &password, ["cli", "http-proxy"])
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;

    let config = env.path("kcc.toml");
    let mut command = env.command(&[
        "--config",
        config.to_str().ok_or("non-UTF-8 path")?,
        "router",
        "add",
        "home",
        "--url",
        &format!("http://{address}"),
    ]);
    let output = command.env("KCC_PASSWORD", &password).output()?;
    let tested = env.kcc(&["--router", "home", "router", "test"])?;

    assert!(
        output.status.success(),
        "add: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(tested.code, 0_i32, "test: {}", tested.stderr);
    assert!(
        env.state_dir()
            .join("router-credentials/home.sealed")
            .is_file()
    );
    assert_state_has_no_secret(&env.state_dir(), password.as_bytes())?;
    Ok(())
}

#[test]
fn first_cli_use_migrates_legacy_plaintext_and_wrong_key_preserves_it() -> TestResult {
    let env = Env::new("")?;
    let credentials = env.state_dir().join("router-credentials");
    fs::create_dir_all(&credentials)?;
    let legacy = credentials.join("home.password");
    fs::write(&legacy, "legacy-password")?;

    let migrated = env.kcc(&["router", "list"])?;

    assert_eq!(migrated.code, 0_i32, "migration: {}", migrated.stderr);
    assert!(!legacy.exists());
    assert!(credentials.join("home.sealed").is_file());

    fs::write(&legacy, "different-password")?;
    let failed = env.kcc(&["router", "list"])?;
    assert_ne!(failed.code, 0_i32, "conflicting migration must fail");
    assert_eq!(fs::read_to_string(&legacy)?, "different-password");
    Ok(())
}

fn assert_state_has_no_secret(path: &Path, secret: &[u8]) -> TestResult {
    if path.is_dir() {
        for listed in fs::read_dir(path)? {
            assert_state_has_no_secret(&listed?.path(), secret)?;
        }
    } else if path.is_file() {
        let bytes = fs::read(path)?;
        assert!(
            !bytes.windows(secret.len()).any(|part| part == secret),
            "secret found in {}",
            path.display()
        );
    } else {
        return Err(format!("unsupported state entry {}", path.display()).into());
    }
    Ok(())
}
