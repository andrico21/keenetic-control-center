//! The role ceiling of a sign-in source.
//!
//! Whoever re-points the identity provider, switches a listener to it or to client
//! certificates, or replaces one of their CAs must cover every role that source hands out,
//! not only the roles the change itself names.

#![expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]

use core::{error::Error, slice};

use kcc_app::{
    mcp_settings::{
        EnvOverrides, McpBase, SettingsError, commit,
        document::{McpOverrides, McpSettingsDocument},
        sources::TrustAnchor,
    },
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
    settings::{
        Config,
        mcp_schema::{MtlsMode, OauthMode, ScopeMapping},
    },
};
use tempfile::TempDir;
use url::Url;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// The provider of every case: issuer, audience, JWKS URL and the `groups` role claim.
pub(crate) const PROVIDER: &str = "[mcp.auth.oidc]\nissuer = \"https://idp.example/realm\"\naudience = \"kcc\"\njwks_uri = \"https://idp.example/jwks\"\nrole_claim = \"groups\"\n";

/// The acting role `mid`: reads and manages MCP on every router.
pub(crate) fn mid() -> Role {
    Role::new(
        "mid".to_owned(),
        [Permission::Read, Permission::ManageMcp],
        vec!["*".to_owned()],
    )
}

/// The built-in administrator.
pub(crate) fn admin() -> Role {
    Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
}

/// The base of kcc.toml `toml`, and a state directory holding `mid` and `roles`.
pub(crate) fn setup(toml: &str, roles: &[Role]) -> TestResult<(McpBase, TempDir, StateStore)> {
    let base = McpBase::new(&Config::from_toml_str(toml)?, &EnvOverrides::default());
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let mut document = RolesDocument::default();
    document.roles.push(mid());
    document.roles.extend_from_slice(roles);
    state.write(&document)?;
    Ok((base, temp, state))
}

/// kcc.toml with the provider, `extra` and one `role_mappings` entry `ops` -> `role`.
pub(crate) fn mapped(role: &str, extra: &str) -> String {
    format!(
        "{extra}{PROVIDER}[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"ops\"\nrole = \"{role}\"\n"
    )
}

/// Plans `change` as `actor` with every toolset known and harmless.
pub(crate) fn plan(
    base: &McpBase,
    state: &StateStore,
    actor: &Role,
    change: &McpOverrides,
) -> Result<(), SettingsError> {
    base.plan_update(state, actor, change, &|_name| Some(false))
        .map(drop)
}

/// The refusal of `result` as `<variant> <role>`, or `ok`.
pub(crate) fn outcome(result: &Result<(), SettingsError>) -> String {
    match result {
        Ok(()) => "ok".to_owned(),
        Err(SettingsError::ProviderAbove { name }) => format!("ProviderAbove {name}"),
        Err(SettingsError::CertificatesAbove { name }) => format!("CertificatesAbove {name}"),
        Err(SettingsError::RoleAbove { name }) => format!("RoleAbove {name}"),
        Err(other) => format!("{other:?}"),
    }
}

/// The changes that decide whose tokens are the provider's, one key each.
fn provider_changes() -> TestResult<Vec<(&'static str, McpOverrides)>> {
    let mut issuer = McpOverrides::default();
    issuer.auth.oidc.issuer = Some(Url::parse("https://attacker.example/realm")?);
    let mut jwks = McpOverrides::default();
    jwks.auth.oidc.jwks_uri = Some(Url::parse("https://attacker.example/jwks")?);
    let mut audience = McpOverrides::default();
    audience.auth.oidc.audience = Some("other".to_owned());
    let mut claim = McpOverrides::default();
    claim.auth.oidc.role_claim = Some("preferred_username".to_owned());
    Ok(vec![
        ("issuer", issuer),
        ("jwks_uri", jwks),
        ("audience", audience),
        ("role_claim", claim),
    ])
}

/// Regression (todo 33): re-pointing the provider under an `admin` mapping is refused.
///
/// Issuer, JWKS URL, audience or role claim, changed while an existing kcc.toml mapping
/// hands out `admin`, are refused for a role below `admin`, whether or not a listener uses
/// the provider now; nothing is written.
#[test]
fn re_pointing_the_provider_under_a_higher_mapping_is_refused() -> TestResult {
    for extra in ["[mcp.auth.main]\noauth = \"external\"\n", ""] {
        let (base, _temp, state) = setup(&mapped("admin", extra), &[])?;
        for (key, change) in provider_changes()? {
            let refused = plan(&base, &state, &mid(), &change);
            assert_eq!(outcome(&refused), "ProviderAbove admin", "{key} {extra:?}");
        }
        assert!(state.read::<McpSettingsDocument>()?.is_none());
    }
    Ok(())
}

/// Regression (todo 33): a scope mapping counts like a claim mapping: with the role claim
/// unset, a kcc.toml scope `kcc` -> `admin` makes an issuer change by `mid` refused.
#[test]
fn a_scope_mapping_counts_like_a_claim_mapping() -> TestResult {
    let toml = format!(
        "{}[[mcp.auth.oidc.scopes]]\nscope = \"kcc\"\nrole = \"admin\"\n",
        PROVIDER.replace("role_claim = \"groups\"\n", "")
    );
    let (base, _temp, state) = setup(&toml, &[])?;
    let mut issuer = McpOverrides::default();
    issuer.auth.oidc.issuer = Some(Url::parse("https://attacker.example/realm")?);

    let refused = plan(&base, &state, &mid(), &issuer);

    assert_eq!(outcome(&refused), "ProviderAbove admin");
    Ok(())
}

/// Regression (todo 33): switching the main or the dedicated listener to the provider while
/// a mapping hands out `admin` is refused for `mid`.
#[test]
fn switching_a_listener_to_the_provider_is_refused_above_the_actor() -> TestResult {
    let (base, _temp, state) = setup(&mapped("admin", ""), &[])?;
    let mut main = McpOverrides::default();
    main.auth.main.oauth = Some(OauthMode::External);
    let mut dedicated = McpOverrides::default();
    dedicated.dedicated.enabled = Some(true);
    dedicated.auth.dedicated.oauth = Some(OauthMode::External);
    let dedicated_toml = format!("[mcp.dedicated]\nenabled = true\n{}", mapped("admin", ""));
    let (enabled_base, _enabled_temp, enabled_state) = setup(&dedicated_toml, &[])?;
    let mut only_oauth = McpOverrides::default();
    only_oauth.auth.dedicated.oauth = Some(OauthMode::External);

    let outcomes = [
        outcome(&plan(&base, &state, &mid(), &main)),
        outcome(&plan(&base, &state, &mid(), &dedicated)),
        outcome(&plan(&enabled_base, &enabled_state, &mid(), &only_oauth)),
    ];

    assert_eq!(outcomes, ["ProviderAbove admin"; 3]);
    Ok(())
}

/// Regression (todo 33): the legitimate provider changes still pass.
///
/// An administrator re-points the provider under an `admin` mapping, `mid` re-points it
/// while every mapping is within its role or there is none, and `mid` adds a mapping to a
/// role it covers.
#[test]
fn provider_changes_within_the_actor_s_role_are_planned() -> TestResult {
    let viewer = mapped("viewer", "[mcp.auth.main]\noauth = \"external\"\n");
    let none = format!("[mcp.auth.main]\noauth = \"external\"\n{PROVIDER}");
    let mut mapping = McpOverrides::default();
    mapping.auth.oidc.scopes = Some(vec![ScopeMapping::new(
        "mcp".to_owned(),
        "viewer".to_owned(),
    )]);
    for (toml, actor) in [
        (mapped("admin", ""), admin()),
        (viewer, mid()),
        (none.clone(), mid()),
    ] {
        let (base, _temp, state) = setup(&toml, &[])?;
        for (key, change) in provider_changes()? {
            let planned = plan(&base, &state, &actor, &change);
            assert_eq!(outcome(&planned), "ok", "{key} by {}: {toml}", actor.name);
        }
    }
    let (base, _temp, state) = setup(&none, &[])?;
    commit(
        &state,
        &base.plan_update(&state, &mid(), &mapping, &|_name| Some(false))?,
    )?;
    Ok(())
}

/// Regression (todo 33): changing an existing scope mapping's role from `viewer` to `admin`
/// is a new purpose for `admin`, so `mid` is refused, although the scope was mapped before.
#[test]
fn raising_an_existing_scope_mapping_is_refused() -> TestResult {
    let (base, _temp, state) = setup("", &[])?;
    let scope = |role: &str| {
        let mut change = McpOverrides::default();
        change.auth.oidc.scopes = Some(vec![ScopeMapping::new("mcp".to_owned(), role.to_owned())]);
        change
    };
    commit(
        &state,
        &base.plan_update(&state, &admin(), &scope("viewer"), &|_name| Some(false))?,
    )?;

    let refused = plan(&base, &state, &mid(), &scope("admin"));

    assert_eq!(outcome(&refused), "RoleAbove admin");
    Ok(())
}

/// Regression (todo 33): switching to client certificates needs their role.
///
/// A kcc.toml `default_role = "admin"` refuses `mid`, and the kit's default `viewer`
/// refuses a role that only manages MCP; `mid` covers `viewer`.
#[test]
fn switching_a_listener_to_certificates_is_refused_above_the_actor() -> TestResult {
    let manager = Role::new(
        "manager".to_owned(),
        [Permission::ManageMcp],
        vec!["*".to_owned()],
    );
    let mut optional = McpOverrides::default();
    optional.auth.main.mtls = Some(MtlsMode::Optional);
    let mut outcomes = Vec::new();
    for (toml, actor) in [
        ("[mcp.auth.mtls]\ndefault_role = \"admin\"\n", mid()),
        ("", manager.clone()),
        ("", mid()),
    ] {
        let (base, _temp, state) = setup(toml, slice::from_ref(&manager))?;
        outcomes.push(outcome(&plan(&base, &state, &actor, &optional)));
    }
    assert_eq!(
        outcomes,
        ["CertificatesAbove admin", "CertificatesAbove viewer", "ok"]
    );
    Ok(())
}

/// Regression (todo 33): replacing a CA needs every role its source hands out.
///
/// Whether or not a listener uses it: the provider's mappings for its CA bundle, the
/// certificates' role for the client CA. An administrator may; without mappings `mid` may
/// replace the provider's bundle.
#[test]
fn replacing_a_ca_needs_every_role_of_its_source() -> TestResult {
    let toml = format!(
        "[mcp.auth.mtls]\ndefault_role = \"admin\"\n{}",
        mapped("admin", "")
    );
    let mapped_setup = setup(&toml, &[])?;
    let bare_setup = setup(PROVIDER, &[])?;
    let check = |(base, _temp, state): &(McpBase, TempDir, StateStore), actor: &Role, anchor| {
        outcome(&base.check_ca_ceiling(state, actor, anchor))
    };

    let outcomes = [
        check(&mapped_setup, &mid(), TrustAnchor::IdentityProvider),
        check(&mapped_setup, &mid(), TrustAnchor::ClientCa),
        check(&mapped_setup, &admin(), TrustAnchor::IdentityProvider),
        check(&mapped_setup, &admin(), TrustAnchor::ClientCa),
        check(&bare_setup, &mid(), TrustAnchor::IdentityProvider),
        check(&bare_setup, &mid(), TrustAnchor::ClientCa),
    ];

    assert_eq!(
        outcomes,
        [
            "ProviderAbove admin",
            "CertificatesAbove admin",
            "ok",
            "ok",
            "ok",
            "ok"
        ]
    );
    Ok(())
}
