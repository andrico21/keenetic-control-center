//! `router add` and `router edit` seal every credential they take and never keep a
//! reference to the input file.

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, net::SocketAddr, sync::atomic::Ordering};
use std::{
    fs,
    process::{self, Output},
};

use kcc_app::{
    audit::read_entries,
    credentials::{CredentialKind, CredentialStore},
    persist::StateStore,
    registry::RouterRegistry,
    secrets::MasterKey,
    settings::OutboundConfig,
};
use kcc_testkit::{
    DEFAULT_LOGIN, FakeRouter,
    auth_fixture::{self, Options as Fixture, Protocol},
    model::Profile,
};
use secrecy::ExposeSecret as _;
use serde_json::{Value, json};

use super::support::{Env, TestResult};

/// The CLI test master key (`Env` writes 32 bytes of 17).
pub(super) fn store(env: &Env) -> Result<CredentialStore, Box<dyn Error>> {
    Ok(CredentialStore::new(
        StateStore::open(&env.state_dir())?,
        MasterKey::from_bytes([17_u8; 32]),
    ))
}

/// The stored profile `id` from `routers.json`.
pub(super) fn stored(env: &Env, id: &str) -> Result<Value, Box<dyn Error>> {
    let document: Value = serde_json::from_slice(&fs::read(env.state_dir().join("routers.json"))?)?;
    document
        .get("routers")
        .and_then(Value::as_array)
        .and_then(|routers| {
            routers
                .iter()
                .find(|router| router.get("id").and_then(Value::as_str) == Some(id))
        })
        .cloned()
        .ok_or_else(|| format!("router {id} is not stored").into())
}

/// The `credentials` audit parameter of the last `action` entry.
pub(super) fn audited_kinds(env: &Env, action: &str) -> Result<Value, Box<dyn Error>> {
    read_entries(&env.state_dir())?
        .iter()
        .rev()
        .find(|entry| entry.action == action)
        .and_then(|entry| entry.params_redacted.get("credentials").cloned())
        .ok_or_else(|| format!("no {action} credentials").into())
}

/// Asserts that `audit.jsonl` holds none of `secrets`.
pub(super) fn assert_audit_has_no(env: &Env, secrets: &[&str]) -> TestResult {
    let audit = fs::read_to_string(env.state_dir().join("audit.jsonl"))?;
    for secret in secrets {
        assert!(!audit.contains(secret), "a secret reached the audit log");
    }
    Ok(())
}

/// The path of `kind`'s sealed record of `id`, as `routers.json` stores it.
fn sealed(env: &Env, id: &str, kind: &str) -> Value {
    Value::String(
        env.state_dir()
            .join("router-credentials")
            .join(format!("{id}.{kind}"))
            .display()
            .to_string(),
    )
}

/// Runs `kcc --config <kcc.toml> <args>` with `KCC_PASSWORD` set to `secret`.
pub(super) fn kcc_with(env: &Env, args: &[&str], secret: &str) -> Result<Output, Box<dyn Error>> {
    let config = env.path("kcc.toml");
    let mut all = vec!["--config", config.to_str().ok_or("non-UTF-8 path")?];
    all.extend_from_slice(args);
    Ok(env.command(&all).env("KCC_PASSWORD", secret).output()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_add_seals_the_password_file_which_can_then_be_deleted() -> TestResult {
    let password = ["sealed", "-add", "-", &process::id().to_string()].concat();
    let (address, _handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, &password, ["cli", "http-proxy"])
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;
    let file = env.write("pw", &format!("{password}\n"))?;
    let url = format!("http://{address}");

    let added = env.kcc(&[
        "--password-file",
        file.to_str().ok_or("non-UTF-8 path")?,
        "router",
        "add",
        "home",
        "--url",
        &url,
    ])?;
    fs::remove_file(&file)?;
    let tested = env.kcc(&["--router", "home", "router", "test"])?;

    assert_eq!(added.code, 0_i32, "{added:?}");
    assert_eq!(
        stored(&env, "home")?.get("password_file"),
        Some(&sealed(&env, "home", "sealed"))
    );
    assert_eq!(
        store(&env)?
            .open("home", CredentialKind::Password)?
            .expose_secret(),
        password
    );
    assert_eq!(tested.code, 0_i32, "{tested:?}");
    assert_eq!(audited_kinds(&env, "cli.router_add")?, json!(["password"]));
    assert_audit_has_no(&env, &[&password])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_add_token_seals_the_token_and_sends_it_as_x_ndma_tkn() -> TestResult {
    let mut fixture = Fixture::default();
    fixture.protocol = Protocol::Token;
    let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
    let env = Env::new("")?;
    let token = ["fixture", "token"].join("-");
    let file = env.write("token", &format!("{token}\n"))?;

    let added = env.kcc(&[
        "router",
        "add",
        "home",
        "--url",
        &format!("http://{address}"),
        "--auth",
        "token",
        "--token-file",
        file.to_str().ok_or("non-UTF-8 path")?,
    ])?;
    fs::remove_file(&file)?;
    drop(env.kcc(&["--router", "home", "router", "test"])?);

    assert_eq!(added.code, 0_i32, "{added:?}");
    let profile = stored(&env, "home")?;
    assert_eq!(
        profile.get("token_file"),
        Some(&sealed(&env, "home", "token.sealed"))
    );
    assert_eq!(profile.get("password_file"), None);
    assert_eq!(
        store(&env)?
            .open("home", CredentialKind::Token)?
            .expose_secret(),
        token
    );
    assert!(counts.token_requests.load(Ordering::SeqCst) >= 1);
    assert_eq!(counts.phase_two.load(Ordering::SeqCst), 0, "no ndw4 login");
    assert_eq!(counts.ndw2_posts.load(Ordering::SeqCst), 0, "no ndw2 login");
    assert_eq!(audited_kinds(&env, "cli.router_add")?, json!(["token"]));
    assert_audit_has_no(&env, &[&token])?;
    handle.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_add_read_login_seals_the_read_password_the_poller_logs_in_with() -> TestResult {
    let id = process::id().to_string();
    let primary = ["primary-", &id].concat();
    let read = ["reader-", &id].concat();
    let (address, _handle) = FakeRouter::builder(Profile::default())
        .user(DEFAULT_LOGIN, &[&primary, "-elsewhere"].concat(), ["cli"])
        .user("reader", &read, ["cli", "http-proxy"])
        .build()?
        .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await?;
    let env = Env::new("")?;
    let file = env.write("read", &read)?;

    let added = kcc_with(
        &env,
        &[
            "router",
            "add",
            "home",
            "--url",
            &format!("http://{address}"),
            "--read-login",
            "reader",
            "--read-password-file",
            file.to_str().ok_or("non-UTF-8 path")?,
        ],
        &primary,
    )?;
    fs::remove_file(&file)?;

    assert!(added.status.success(), "{added:?}");
    assert_eq!(
        stored(&env, "home")?.get("read_password_file"),
        Some(&sealed(&env, "home", "read.sealed"))
    );
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    let state = StateStore::open(&env.state_dir())?;
    let registry =
        RouterRegistry::new(state, &[], &outbound)?.with_credentials(Arc::new(store(&env)?));
    let info = registry.poll_info("home").await?;
    assert_eq!(info.hw_id(), Some("KN-1811"));
    assert_eq!(
        audited_kinds(&env, "cli.router_add")?,
        json!(["password", "read"])
    );
    assert_audit_has_no(&env, &[&primary, &read])
}
