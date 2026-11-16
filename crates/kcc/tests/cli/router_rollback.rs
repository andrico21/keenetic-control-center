//! A `router edit` that fails leaves every sealed record as it was, and `KCC_PASSWORD`
//! never fills more than one credential.

use core::{error::Error, net::SocketAddr};
use std::{fs, path::Path, process};

use kcc_testkit::{DEFAULT_LOGIN, FakeRouter, model::Profile};

use super::{
    router_sealing::kcc_with,
    support::{Env, TestResult},
};

/// The bytes of every sealed record kind of `home` (`None` when absent).
fn records(env: &Env) -> Result<Vec<Option<Vec<u8>>>, Box<dyn Error>> {
    let directory = env.state_dir().join("router-credentials");
    ["home.sealed", "home.token.sealed", "home.read.sealed"]
        .into_iter()
        .map(|name| {
            let path = directory.join(name);
            Ok(path.exists().then(|| fs::read(&path)).transpose()?)
        })
        .collect()
}

/// Adds router `home` at `url` with a sealed password and a sealed read-only password.
fn add_home(env: &Env, url: &str, primary: &str, reader: &Path) -> TestResult {
    let added = kcc_with(
        env,
        &[
            "router",
            "add",
            "home",
            "--url",
            url,
            "--read-login",
            "reader",
            "--read-password-file",
            reader.to_str().ok_or("non-UTF-8 path")?,
        ],
        primary,
    )?;
    assert!(added.status.success(), "{added:?}");
    Ok(())
}

/// F-02, N17: a URL that is not an origin is refused before anything is sealed.
///
/// `router edit --url http://host/ui --new-password` used to seal the new password and
/// then fail the profile update, so the old profile signed in with the new secret.
#[test]
fn a_mistyped_url_seals_nothing() -> TestResult {
    let id = process::id().to_string();
    let env = Env::new("")?;
    let reader = env.write("read", &["read-", &id].concat())?;
    add_home(
        &env,
        "http://127.0.0.1:9",
        &["first-", &id].concat(),
        &reader,
    )?;
    let before = records(&env)?;
    let profiles = fs::read(env.state_dir().join("routers.json"))?;

    let refused = kcc_with(
        &env,
        &[
            "router",
            "edit",
            "home",
            "--url",
            "http://127.0.0.1:10/ui",
            "--new-password",
        ],
        &["second-", &id].concat(),
    )?;

    assert!(!refused.status.success(), "{refused:?}");
    assert_eq!(records(&env)?, before, "sealed records unchanged");
    assert_eq!(fs::read(env.state_dir().join("routers.json"))?, profiles);
    Ok(())
}

/// SEC1-09, W1-05, N17: a profile update that fails after sealing restores every sealed
/// record byte for byte, so the old profile still signs in with its old secret.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_profile_write_restores_every_sealed_record() -> TestResult {
    let id = process::id().to_string();
    let primary = ["primary-", &id].concat();
    let (address, _handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, &primary, ["cli", "http-proxy"])
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;
    let reader = env.write("read", &["read-", &id].concat())?;
    add_home(&env, &format!("http://{address}"), &primary, &reader)?;
    let before = records(&env)?;
    let new_reader = env.write("read-new", &["read-new-", &id].concat())?;
    let blocker = env.state_dir().join(".routers.json.tmp");
    fs::create_dir_all(blocker.join("held"))?;

    let failed = kcc_with(
        &env,
        &[
            "router",
            "edit",
            "home",
            "--new-password",
            "--read-password-file",
            new_reader.to_str().ok_or("non-UTF-8 path")?,
        ],
        &["second-", &id].concat(),
    )?;

    assert!(!failed.status.success(), "{failed:?}");
    assert_eq!(records(&env)?, before, "sealed records restored");
    fs::remove_dir_all(&blocker)?;
    let tested = env.kcc(&["--router", "home", "router", "test"])?;
    assert_eq!(tested.code, 0_i32, "old secret signs in: {tested:?}");
    Ok(())
}

/// F-17: `KCC_PASSWORD` cannot stand in for two credentials of one command.
#[test]
fn kcc_password_never_fills_two_credentials() -> TestResult {
    let id = process::id().to_string();
    let env = Env::new("")?;
    let reader = env.write("read", &["read-", &id].concat())?;
    add_home(
        &env,
        "http://127.0.0.1:9",
        &["first-", &id].concat(),
        &reader,
    )?;
    let before = records(&env)?;

    let edited = kcc_with(
        &env,
        &[
            "router",
            "edit",
            "home",
            "--new-password",
            "--new-read-password",
        ],
        &["shared-", &id].concat(),
    )?;
    let added = kcc_with(
        &env,
        &[
            "router",
            "add",
            "office",
            "--url",
            "http://127.0.0.1:11",
            "--read-login",
            "reader",
        ],
        &["shared-", &id].concat(),
    )?;

    assert_eq!(edited.status.code(), Some(2_i32), "{edited:?}");
    assert_eq!(records(&env)?, before, "nothing sealed");
    assert_eq!(added.status.code(), Some(2_i32), "{added:?}");
    assert!(
        !env.state_dir()
            .join("router-credentials/office.sealed")
            .exists()
    );
    Ok(())
}
