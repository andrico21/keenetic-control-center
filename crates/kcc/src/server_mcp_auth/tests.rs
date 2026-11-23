//! kcc sign-in: the kit configuration, the internal JWKS listener and the per-call
//! resolution of an account.

extern crate alloc;

use alloc::sync::Arc;
use core::{
    error::Error,
    iter,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use std::net::TcpListener;

use kcc_app::{
    accounts::{AccountChange, AccountStore, NewAccount, SystemClock, UsersDocument},
    mcp_auth::{
        clients::{ClientRegistration, ClientStore},
        grants::GrantStore,
        pending::{AuthorizationRequest, CodeTarget, PendingStore, PkceChallenge},
    },
    mcp_settings::ListenerKind,
    permissions::{Permission, Role},
    persist::StateStore,
    secrets::MasterKey,
    settings::{Config, McpConfig, mcp_schema::DedicatedTls},
};
use kcc_mcp::principals::{McpPrincipals as _, PrincipalRefusal};
use kcc_web::oauth::OAuthServer;
use secrecy::SecretString;
use tempfile::TempDir;

use super::{KccSignIn, jwks, principals::FilePrincipals, resources};

/// Test result.
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

/// The loopback main listener's configuration.
fn config() -> TestResult<Config> {
    Ok(Config::from_toml_str("[web]\nenabled = true\n")?)
}

/// kcc sign-in over a fresh state directory.
fn sign_in(directory: &TempDir) -> TestResult<KccSignIn> {
    let state = StateStore::open(&directory.path().join("state"))?;
    let server = OAuthServer::of(
        &config()?,
        (state, MasterKey::generate()?),
        Arc::new(SystemClock::default()),
    )
    .ok_or("no issuer")?;
    Ok(KccSignIn::new(Arc::new(server)))
}

/// Whether `[::1]` can be bound here.
fn ipv6() -> bool {
    TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).is_ok()
}

/// Regression (todo 31): the JWKS listener holds one port on every loopback address and
/// on nothing else.
#[test]
fn the_jwks_listener_binds_one_port_on_the_loopback_addresses_only() -> TestResult {
    let bound = jwks::bind(iter::repeat(0))?;
    let port = bound.port();
    let addresses = bound
        .into_listeners()
        .iter()
        .map(TcpListener::local_addr)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(addresses.len(), if ipv6() { 2 } else { 1 });
    assert!(
        addresses.iter().all(|address| address.ip().is_loopback()),
        "{addresses:?}"
    );
    assert!(addresses.iter().all(|address| address.port() == port));
    Ok(())
}

/// Regression (todo 31): five candidate ports each taken on [::1] refuse kcc sign-in with
/// the reason; skipped (reason logged) where [::1] cannot be bound.
#[tokio::test]
async fn five_ports_taken_on_ipv6_refuse_kcc_sign_in() -> TestResult {
    if !ipv6() {
        tracing::info!("live-skip: no IPv6 loopback on this host");
        return Ok(());
    }
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    let held = iter::repeat_n(v6, jwks::ATTEMPTS)
        .map(TcpListener::bind)
        .collect::<Result<Vec<_>, _>>()?;
    let ports = held
        .iter()
        .map(|listener| listener.local_addr().map(|address| address.port()))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(matches!(
        jwks::bind(ports.clone()),
        Err(jwks::JwksError::Taken)
    ));
    let directory = TempDir::new()?;
    let refused = sign_in(&directory)?.jwks_port(ports);
    assert!(
        refused
            .as_ref()
            .is_err_and(|reason| reason.contains("[::1]")),
        "{refused:?}"
    );
    Ok(())
}

/// Regression (todo 31): the kit's configuration pins kcc's token rules.
///
/// kcc's issuer, `EdDSA` only, a subject required, the listener's canonical resource with
/// its aliases as audiences, keys from the internal listener on `localhost` (the only SSRF
/// exception), and the scope `mcp` mapped to the reserved role.
#[tokio::test]
async fn the_kit_configuration_pins_issuer_algorithm_subject_and_audience() -> TestResult {
    let directory = TempDir::new()?;
    let sign_in = sign_in(&directory)?;
    let (oauth, accepted) =
        sign_in.listener(&config()?, &McpConfig::default(), ListenerKind::Main)?;
    let port = sign_in.jwks_port(iter::repeat(0))?;
    assert_eq!(oauth.issuer, "http://localhost:8443");
    assert_eq!(
        oauth.authorization_servers,
        Some(vec!["http://localhost:8443".to_owned()])
    );
    assert_eq!(oauth.audience, "http://127.0.0.1:8443/mcp");
    assert_eq!(
        oauth.additional_audiences,
        vec![
            "http://[::1]:8443/mcp".to_owned(),
            "http://localhost:8443/mcp".to_owned()
        ]
    );
    assert_eq!(oauth.jwks_uri, format!("http://localhost:{port}/jwks"));
    assert_eq!(oauth.allowed_algorithms, Some(vec!["EdDSA".to_owned()]));
    assert!(oauth.require_subject);
    assert!(oauth.allow_http_oauth_urls);
    let allowlist = oauth.ssrf_allowlist.ok_or("no SSRF allowlist")?;
    assert_eq!(allowlist.hosts, vec!["localhost".to_owned()]);
    assert_eq!(allowlist.cidrs, Vec::<String>::new());
    assert_eq!(oauth.scopes.len(), 1);
    assert_eq!(
        oauth
            .scopes
            .first()
            .map(|scope| (scope.scope.as_str(), scope.role.as_str())),
        Some(("mcp", "kcc-account"))
    );
    assert_eq!(accepted.resources.len(), 3);
    assert!(accepted.resources.contains("http://127.0.0.1:8443/mcp"));
    Ok(())
}

/// Regression (todo 31): a public URL is the canonical resource as the kit advertises it;
/// a dedicated listener with its own certificate is `https`.
#[test]
fn resources_follow_the_kit_s_canonical_url() -> TestResult {
    let config = Config::from_toml_str(
        "[server]\npublic_url = \"https://mcp.example.com\"\n\n[web]\nenabled = true\n",
    )?;
    let (canonical, aliases) = resources(&config, &McpConfig::default(), ListenerKind::Main);
    assert_eq!(canonical, "https://mcp.example.com/mcp");
    assert!(
        aliases.contains(&"http://127.0.0.1:8443/mcp".to_owned()),
        "{aliases:?}"
    );
    let mut settings = McpConfig::default();
    settings.dedicated.tls = DedicatedTls::SelfSigned;
    let (dedicated, _) = resources(&config, &settings, ListenerKind::Dedicated);
    assert_eq!(dedicated, "https://127.0.0.1:8444/mcp");
    Ok(())
}

/// A state with the operator `olga` holding one grant; the principals over it.
struct Granted {
    /// Holds the state.
    directory: TempDir,
    /// The accounts.
    accounts: Arc<AccountStore>,
    /// The grants.
    grants: GrantStore,
    /// The grant's id.
    id: String,
    /// The principals under test.
    principals: FilePrincipals,
}

/// Creates [`Granted`].
fn granted() -> TestResult<Granted> {
    let directory = TempDir::new()?;
    let state = StateStore::open(&directory.path().join("state"))?;
    let clock = Arc::new(SystemClock::default());
    let accounts = Arc::new(AccountStore::new(
        state.clone(),
        MasterKey::generate()?,
        Duration::from_mins(15),
        Arc::<SystemClock>::clone(&clock),
    ));
    let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
    for (name, role) in [("alice", "admin"), ("olga", "operator")] {
        accounts.create(
            &admin,
            NewAccount::new(
                name.to_owned(),
                SecretString::from("correct horse battery staple"),
                role.to_owned(),
            ),
        )?;
    }
    let redirect = "http://127.0.0.1:9/cb";
    let client = ClientStore::new(state.clone(), Arc::<SystemClock>::clone(&clock))
        .register(&ClientRegistration::new(None, vec![redirect.to_owned()]))?;
    let pending = PendingStore::new(Arc::<SystemClock>::clone(&clock));
    let verifier = SecretString::from("v".repeat(43));
    let challenge = PkceChallenge::parse("S256", "7w_YNF9DSfIdPf_pRjSq646_kPr-2-o9NAl16JGghdM")?;
    let target = CodeTarget::new(client.id(), redirect, "http://127.0.0.1:8443/mcp");
    let code = pending.issue_code(
        AuthorizationRequest::new(&client, target.clone(), challenge)?,
        "olga",
    )?;
    let authorized = pending
        .redeem(&code, &target, &verifier)
        .map_err(|refusal| format!("{refusal:?}"))?;
    let grants = GrantStore::new(state.clone(), clock, Duration::from_hours(1));
    let fingerprint = accounts.fingerprint("olga")?.ok_or("olga")?;
    let id = grants
        .issue(&authorized, &fingerprint)?
        .grant()
        .id()
        .to_owned();
    Ok(Granted {
        principals: FilePrincipals::new(Arc::clone(&accounts), state),
        directory,
        accounts,
        grants,
        id,
    })
}

/// Regression (todo 31): every call reads a changed `users.json` or grants file again.
///
/// A role change shows at once; a disabled account, an account that must change its
/// password, an unknown or revoked grant, another account's grant are refused.
#[test]
fn principals_follow_every_change_at_the_next_call() -> TestResult {
    let set = granted()?;
    let resolve = || set.principals.resolve("olga", &set.id);
    assert_eq!(resolve(), Ok("operator".to_owned()));
    assert_eq!(
        set.principals.resolve("alice", &set.id),
        Err(PrincipalRefusal::Account)
    );
    assert_eq!(
        set.principals.resolve("olga", &"0".repeat(64)),
        Err(PrincipalRefusal::Grant)
    );
    drop(
        set.accounts
            .administer("olga", &AccountChange::Role("viewer".to_owned()))?,
    );
    assert_eq!(
        resolve(),
        Ok("viewer".to_owned()),
        "a role change is read again"
    );
    drop(
        set.accounts
            .administer("olga", &AccountChange::Disabled(true))?,
    );
    assert_eq!(resolve(), Err(PrincipalRefusal::Account), "disabled");
    drop(
        set.accounts
            .administer("olga", &AccountChange::Disabled(false))?,
    );
    assert_eq!(resolve(), Ok("viewer".to_owned()));
    let state = StateStore::open(&set.directory.path().join("state"))?;
    let must_change = |on: bool| {
        state.update(|document: &mut UsersDocument| {
            for account in &mut document.users {
                if account.username == "olga" {
                    account.must_change_password = on;
                }
            }
        })
    };
    must_change(true)?;
    assert_eq!(
        resolve(),
        Err(PrincipalRefusal::Account),
        "must change its password"
    );
    must_change(false)?;
    assert_eq!(resolve(), Ok("viewer".to_owned()));
    assert!(set.grants.revoke(&set.id)?);
    assert_eq!(resolve(), Err(PrincipalRefusal::Grant), "revoked");
    Ok(())
}

/// Regression (todo 31): a password changed after the grant was issued refuses it.
#[test]
fn a_changed_password_refuses_the_grant() -> TestResult {
    let set = granted()?;
    drop(set.accounts.change_password(
        "olga",
        &SecretString::from("correct horse battery staple"),
        &SecretString::from("another horse battery staple"),
    )?);
    assert_eq!(
        set.principals.resolve("olga", &set.id),
        Err(PrincipalRefusal::Account)
    );
    Ok(())
}
