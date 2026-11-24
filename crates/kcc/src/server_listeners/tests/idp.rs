//! Listeners with `oauth = "external"`.
//!
//! The kit configuration built from the effective settings, the kcc.toml-only SSRF
//! allowlist, and the replacement of the identity provider's CA bundle (password, restart,
//! the previous bundle put back on failure).

extern crate alloc;

use alloc::sync::Arc;
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};
use std::{
    fs, io,
    net::TcpListener,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use kcc_app::{
    mcp_settings::{
        ListenerKind,
        idp_ca::{oidc_ca_path, store_oidc_ca},
    },
    settings::{Config, McpConfig},
};
use kcc_testkit::fake_idp::{FakeIdp, tokens::Claims};
use reqwest::{Client, StatusCode};
use serde_json::json;

use super::{
    SHORT, TestResult,
    client::http,
    fixture::{Fixture, Setup, free_port},
    hook,
};
use crate::server_listeners::{
    ListenerError, Restarted, RevertReason,
    build::BuildError,
    sign_in::{
        external::{ProviderRefusal, provider},
        tokens,
    },
    supervisor::Stage,
};

/// The audience the provider's tokens name.
const AUDIENCE: &str = "kcc-mcp";

/// `[mcp.auth.oidc]` for `idp` (issuer under its port, scope `mcp` -> `admin`) with
/// `allowlist` lines.
fn oidc(idp: &FakeIdp, allowlist: &str) -> String {
    format!(
        "[mcp.auth.oidc]\nissuer = \"{}\"\naudience = \"{AUDIENCE}\"\njwks_uri = \"{}\"\nallowed_algorithms = [\"ES256\"]\n{allowlist}\n[[mcp.auth.oidc.scopes]]\nscope = \"mcp\"\nrole = \"admin\"\n",
        issuer(idp),
        idp.jwks_uri()
    )
}

/// The issuer `idp`'s tokens name.
fn issuer(idp: &FakeIdp) -> String {
    format!("https://localhost:{}/realms/kcc", idp.address().port())
}

/// kcc.toml's `[mcp]` with `oauth = "external"` on main and `oidc`.
fn settings(oidc: &str) -> TestResult<(Config, McpConfig)> {
    let config = Config::from_toml_str(&format!(
        "[mcp]\nhttp_enabled = true\n\n[mcp.auth.main]\noauth = \"external\"\n\n{oidc}"
    ))?;
    let mcp = config.mcp.clone();
    Ok((config, mcp))
}

/// A token of `idp` for the `mcp` scope, valid for an hour.
fn token(idp: &FakeIdp) -> TestResult<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut claims = Claims::new(&issuer(idp), AUDIENCE, "alice", now.saturating_add(3600));
    claims.scope = Some("mcp".to_owned());
    Ok(idp.token(&claims)?)
}

/// The status of an MCP `initialize` at `address` with the bearer `token`.
async fn initialize(client: &Client, address: SocketAddr, token: &str) -> TestResult<StatusCode> {
    Ok(client
        .post(format!("http://{address}/mcp"))
        .bearer_auth(token)
        .header("accept", "application/json, text/event-stream")
        .json(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"oidc","version":"1"}}}))
        .send()
        .await?
        .status())
}

/// Todo 33: the kit configuration follows the provider settings.
///
/// It names the provider's issuer, audience, JWKS URL, algorithms and scope mapping,
/// requires a subject, sends MCP clients to the provider as authorization server and trusts
/// the stored CA bundle.
#[tokio::test]
async fn the_provider_configuration_follows_the_settings() -> TestResult {
    let idp = FakeIdp::spawn().await?;
    let (config, mcp) = settings(&oidc(&idp, "ssrf_allow_hosts = [\"localhost\"]"))?;
    let directory = tempfile::TempDir::new()?;
    let state = kcc_app::persist::StateStore::open(directory.path())?;
    let _subjects = store_oidc_ca(&state, idp.ca_pem().as_bytes())?;

    let oauth = provider(&state, &mcp, &config.mcp.auth.oidc)?;

    assert_eq!(oauth.issuer, issuer(&idp));
    assert_eq!(oauth.audience, AUDIENCE);
    assert_eq!(oauth.jwks_uri, idp.jwks_uri());
    assert_eq!(oauth.authorization_servers, Some(vec![issuer(&idp)]));
    assert!(oauth.require_subject);
    assert_eq!(oauth.allowed_algorithms, Some(vec!["ES256".to_owned()]));
    assert_eq!(oauth.scopes.len(), 1);
    assert_eq!(oauth.role_claim, None);
    assert_eq!(oauth.ca_cert_path, Some(oidc_ca_path(&state)));
    assert_eq!(
        oauth.ssrf_allowlist.map(|allowlist| allowlist.hosts),
        Some(vec!["localhost".to_owned()])
    );
    Ok(())
}

/// Todo 33: a JWKS host on a loopback address is refused when building, with its typed
/// reason, unless kcc.toml's allowlist names the host or the networks.
#[tokio::test]
async fn a_private_jwks_host_needs_the_kcc_toml_allowlist() -> TestResult {
    let idp = FakeIdp::spawn().await?;
    let directory = tempfile::TempDir::new()?;
    let state = kcc_app::persist::StateStore::open(directory.path())?;
    let (config, mcp) = settings(&oidc(&idp, ""))?;

    let refused = provider(&state, &mcp, &config.mcp.auth.oidc);

    assert!(
        matches!(
            &refused,
            Err(ProviderRefusal::PrivateAddress { host, reason: "loopback" }) if host == "localhost"
        ),
        "{refused:?}"
    );
    for allowlist in [
        "ssrf_allow_hosts = [\"LOCALHOST\"]",
        "ssrf_allow_cidrs = [\"127.0.0.0/8\", \"::1/128\"]",
    ] {
        let (allowing, _mcp) = settings(&oidc(&idp, allowlist))?;
        drop(provider(&state, &mcp, &allowing.mcp.auth.oidc)?);
    }
    let (cidr, _mcp) = settings(&oidc(&idp, "ssrf_allow_cidrs = [\"10.0.0.0/8\"]"))?;
    assert!(matches!(
        provider(&state, &mcp, &cidr.mcp.auth.oidc),
        Err(ProviderRefusal::PrivateAddress {
            host: _,
            reason: "loopback"
        })
    ));
    Ok(())
}

/// Todo 33: the listener build takes the SSRF allowlist from kcc.toml only: settings that
/// carry one (as no Web change can) do not admit a loopback provider kcc.toml does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_build_reads_the_allowlist_from_kcc_toml_only() -> TestResult {
    let idp = FakeIdp::spawn().await?;
    let fixture = Fixture::start(Setup::default()).await?;
    let (_config, allowing) = settings(&oidc(&idp, "ssrf_allow_hosts = [\"localhost\"]"))?;

    let refused = tokens(&fixture.shared, &allowing, ListenerKind::Main);

    assert!(
        matches!(
            refused,
            Err(BuildError::IdentityProvider(
                ProviderRefusal::PrivateAddress {
                    host: _,
                    reason: "loopback"
                }
            ))
        ),
        "{refused:?}"
    );
    fixture.stop().await??;
    Ok(())
}

/// Todo 33: missing provider settings and a stored CA bundle that fails the checks refuse
/// the build with their reason.
#[tokio::test]
async fn missing_settings_and_a_broken_bundle_are_refused() -> TestResult {
    let idp = FakeIdp::spawn().await?;
    let directory = tempfile::TempDir::new()?;
    let state = kcc_app::persist::StateStore::open(directory.path())?;
    let allow = "ssrf_allow_hosts = [\"localhost\"]";
    for (removed, field) in [
        ("issuer", "issuer"),
        ("audience", "audience"),
        ("jwks_uri", "jwks_uri"),
    ] {
        let prefix = format!("{removed} =");
        let text = oidc(&idp, allow)
            .lines()
            .filter(|line| !line.starts_with(&prefix))
            .collect::<Vec<_>>()
            .join("\n");
        let (config, mcp) = settings(&text)?;
        let refused = provider(&state, &mcp, &config.mcp.auth.oidc);
        assert!(
            matches!(refused, Err(ProviderRefusal::Missing(name)) if name == field),
            "{field}"
        );
    }
    let (config, mcp) = settings(&oidc(&idp, allow))?;
    fs::create_dir_all(oidc_ca_path(&state).parent().ok_or("no parent")?)?;
    fs::write(oidc_ca_path(&state), "not a certificate")?;
    assert!(matches!(
        provider(&state, &mcp, &config.mcp.auth.oidc),
        Err(ProviderRefusal::CaBundle(_))
    ));
    Ok(())
}

/// Main with `oauth = "external"` for `idp` and the CA bundle `bundle` stored (the running
/// listener read none at its start), with the metrics port held at the `Stopped` stage once
/// `armed`.
async fn external_main(
    idp: &FakeIdp,
    bundle: &str,
    armed: &Arc<AtomicBool>,
) -> TestResult<(Fixture, Arc<Mutex<Vec<io::Result<TcpListener>>>>)> {
    let metrics = SocketAddr::from(([127, 0, 0, 1], free_port()?));
    let held: Arc<Mutex<Vec<io::Result<TcpListener>>>> = Arc::default();
    let (arming, holding) = (Arc::clone(armed), Arc::clone(&held));
    let setup = Setup {
        tail: format!(
            "[mcp.auth.main]\noauth = \"external\"\n\n{}",
            oidc(idp, "ssrf_allow_hosts = [\"localhost\"]")
        ),
        metrics: Some(metrics),
        windows: Some(SHORT),
        hook: hook(move |stage| {
            if stage == Stage::Stopped && arming.load(Ordering::SeqCst) {
                let taken = TcpListener::bind(metrics);
                if let Ok(mut slot) = holding.lock() {
                    slot.push(taken);
                }
            }
            async {}
        }),
        ..Setup::default()
    };
    let fixture = Fixture::start(setup).await?;
    let _subjects = store_oidc_ca(&fixture.state, bundle.as_bytes())?;
    Ok((fixture, held))
}

/// Todo 33: replacing the CA bundle in use needs the password, restarts the listener and
/// then trusts the new provider certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bundle_replacement_needs_the_password_and_restarts() -> TestResult {
    let (previous, served) = (FakeIdp::spawn().await?, FakeIdp::spawn().await?);
    let armed = Arc::new(AtomicBool::new(false));
    let (fixture, _held) = external_main(&served, previous.ca_pem(), &armed).await?;
    let client = http()?;
    let generation = fixture
        .supervisor
        .status()
        .main
        .ok_or("no main")?
        .generation;
    assert_eq!(
        initialize(&client, fixture.main()?, &token(&served)?).await?,
        StatusCode::UNAUTHORIZED,
        "the provider's certificate is not trusted yet"
    );

    let unconfirmed = fixture
        .supervisor
        .replace_idp_ca(served.ca_pem().as_bytes().to_vec(), false)
        .await;
    assert!(
        matches!(unconfirmed, Err(ListenerError::ConfirmationRequired)),
        "{unconfirmed:?}"
    );
    assert_eq!(
        fs::read_to_string(oidc_ca_path(&fixture.state))?,
        previous.ca_pem()
    );

    let applied = fixture
        .supervisor
        .replace_idp_ca(served.ca_pem().as_bytes().to_vec(), true)
        .await?;

    assert!(matches!(applied, Restarted::Applied), "{applied:?}");
    assert_eq!(
        fs::read_to_string(oidc_ca_path(&fixture.state))?,
        served.ca_pem()
    );
    let restarted = fixture
        .supervisor
        .status()
        .main
        .ok_or("no main")?
        .generation;
    assert_eq!(restarted, generation.saturating_add(1));
    assert_eq!(
        initialize(&client, fixture.main()?, &token(&served)?).await?,
        StatusCode::OK
    );
    fixture.stop().await??;
    Ok(())
}

/// Todo 33: after a failed bundle replacement the listener trusts the previous bundle.
///
/// The restart fails its health check; the previous bundle is put back before the previous
/// listener serves again, so a token whose JWKS server presents a certificate from the
/// rejected bundle's CA is still refused, and the file on disk is the previous one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_replacement_keeps_the_previous_bundle() -> TestResult {
    let (previous, rejected) = (FakeIdp::spawn().await?, FakeIdp::spawn().await?);
    let armed = Arc::new(AtomicBool::new(false));
    let (fixture, held) = external_main(&rejected, previous.ca_pem(), &armed).await?;
    let client = http()?;

    armed.store(true, Ordering::SeqCst);
    let failed = fixture
        .supervisor
        .replace_idp_ca(rejected.ca_pem().as_bytes().to_vec(), true)
        .await?;

    assert!(
        matches!(
            failed,
            Restarted::Reverted(RevertReason::Health {
                listener: ListenerKind::Main,
                reason: _
            })
        ),
        "{failed:?}"
    );
    assert!(
        held.lock()
            .map_err(|_poisoned| "poisoned")?
            .iter()
            .any(Result::is_ok),
        "the test held the metrics port"
    );
    assert_eq!(
        fs::read_to_string(oidc_ca_path(&fixture.state))?,
        previous.ca_pem()
    );
    assert_eq!(
        initialize(&client, fixture.main()?, &token(&rejected)?).await?,
        StatusCode::UNAUTHORIZED,
        "the rejected bundle's CA"
    );
    fixture.stop().await??;
    Ok(())
}

/// Todo 33: a replacement whose new listener cannot be built puts the previous bundle back,
/// and a refused file is never written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replacement_that_cannot_build_puts_the_bundle_back() -> TestResult {
    let (previous, rejected) = (FakeIdp::spawn().await?, FakeIdp::spawn().await?);
    let armed = Arc::new(AtomicBool::new(false));
    let (fixture, _held) = external_main(&rejected, previous.ca_pem(), &armed).await?;
    let before = fs::read(oidc_ca_path(&fixture.state))?;

    let refused = fixture
        .supervisor
        .replace_idp_ca(
            b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
            true,
        )
        .await;
    assert!(
        matches!(refused, Err(ListenerError::IdpCa(_))),
        "{refused:?}"
    );
    assert_eq!(fs::read(oidc_ca_path(&fixture.state))?, before);

    fs::write(fixture.state.dir().join("api_keys.json"), "{")?;
    let failed = fixture
        .supervisor
        .replace_idp_ca(rejected.ca_pem().as_bytes().to_vec(), true)
        .await;

    assert!(
        matches!(
            failed,
            Err(ListenerError::Build {
                listener: "main",
                source: _
            })
        ),
        "{failed:?}"
    );
    assert_eq!(fs::read(oidc_ca_path(&fixture.state))?, before);
    fixture.stop().await??;
    Ok(())
}
