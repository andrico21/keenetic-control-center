//! The roles a sign-in source hands out, as the ceiling anchors them.
//!
//! When an anchored role counts (the state after the change), when a listener counts as
//! newly using a source (enabling it, not merely having it configured), what an unrelated
//! change may do while a source is in use, an unknown mapping target, and the re-check of
//! the anchored roles at commit.

#![expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]

use kcc_app::{
    mcp_settings::{
        commit,
        document::{McpOverrides, McpSettingsDocument},
    },
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
    settings::mcp_schema::{OauthMode, RoleMapping},
};
use url::Url;

use crate::provider::{PROVIDER, TestResult, admin, mapped, mid, outcome, plan, setup};

/// Writes `overrides` as the state file at revision 1.
fn save(state: &StateStore, overrides: McpOverrides) -> TestResult {
    let mut document = McpSettingsDocument::default();
    document.revision = 1;
    document.overrides = overrides;
    state.write(&document)?;
    Ok(())
}

/// A change that only moves the issuer elsewhere.
fn issuer_change() -> TestResult<McpOverrides> {
    let mut change = McpOverrides::default();
    change.auth.oidc.issuer = Some(Url::parse("https://attacker.example/realm")?);
    Ok(change)
}

/// The role `name` on every router with `permissions`.
fn role<const N: usize>(name: &str, permissions: [Permission; N]) -> Role {
    Role::new(name.to_owned(), permissions, vec!["*".to_owned()])
}

/// Regression (todo 33): enabling a dedicated listener already set to a source anchors it.
///
/// kcc.toml (or an earlier override) sets the disabled dedicated listener to the provider
/// under an `admin` mapping, or to required client certificates under `default_role =
/// "admin"`. `mid` turning only `dedicated.enabled` on is refused, an administrator may,
/// and a change that leaves the listener off is no re-point.
#[test]
fn enabling_a_configured_dedicated_listener_needs_its_roles() -> TestResult {
    let off = "[mcp.dedicated]\nenabled = false\n";
    let oauth_toml = mapped(
        "admin",
        &format!("{off}[mcp.auth.dedicated]\noauth = \"external\"\n"),
    );
    let mtls_toml = format!(
        "{off}[mcp.auth.dedicated]\nmtls = \"required\"\n[mcp.auth.mtls]\ndefault_role = \"admin\"\n"
    );
    let mut enable = McpOverrides::default();
    enable.dedicated.enabled = Some(true);
    let mut bytes = McpOverrides::default();
    bytes.max_result_bytes = Some(4096);
    let mut outcomes = Vec::new();
    for (case, toml, earlier) in [
        ("oauth in kcc.toml", oauth_toml, None),
        (
            "oauth in an override",
            mapped("admin", off),
            Some(OauthMode::External),
        ),
        ("mtls in kcc.toml", mtls_toml, None),
    ] {
        for (actor, change) in [(mid(), &enable), (admin(), &enable), (mid(), &bytes)] {
            let (base, _temp, state) = setup(&toml, &[])?;
            if let Some(mode) = earlier {
                let mut overrides = McpOverrides::default();
                overrides.auth.dedicated.oauth = Some(mode);
                save(&state, overrides)?;
            }
            let result = plan(&base, &state, &actor, change);
            outcomes.push(format!("{case}, {}: {}", actor.name, outcome(&result)));
        }
    }
    assert_eq!(
        outcomes,
        [
            "oauth in kcc.toml, mid: ProviderAbove admin",
            "oauth in kcc.toml, admin: ok",
            "oauth in kcc.toml, mid: ok",
            "oauth in an override, mid: ProviderAbove admin",
            "oauth in an override, admin: ok",
            "oauth in an override, mid: ok",
            "mtls in kcc.toml, mid: CertificatesAbove admin",
            "mtls in kcc.toml, admin: ok",
            "mtls in kcc.toml, mid: ok",
        ]
    );
    Ok(())
}

/// Regression (todo 33): the commit re-checks the anchored roles as they are then.
///
/// `mid` plans an issuer change under a mapping to `lab` (Read only, which `mid` covers);
/// before the commit `lab` grows to every permission, or the unknown mapped role `ghost`
/// is created with every permission. The commit is refused and nothing is written.
#[test]
fn commit_re_checks_the_anchored_roles() -> TestResult {
    let mut outcomes = Vec::new();
    for (target, at_plan) in [
        ("lab", Some(role("lab", [Permission::Read]))),
        ("ghost", None),
    ] {
        let toml = mapped(target, "[mcp.auth.main]\noauth = \"external\"\n");
        let (base, _temp, state) = setup(&toml, at_plan.as_slice())?;
        let candidate =
            base.plan_update(&state, &mid(), &issuer_change()?, &|_name| Some(false))?;
        state.update(|roles: &mut RolesDocument| {
            roles.roles.retain(|role| role.name != target);
            roles.roles.push(role(target, Permission::ALL));
        })?;

        let committed = commit(&state, &candidate);

        let written = state.read::<McpSettingsDocument>()?.is_some();
        outcomes.push((outcome(&committed), written));
    }
    assert_eq!(
        outcomes,
        [
            ("ProviderAbove lab".to_owned(), false),
            ("ProviderAbove ghost".to_owned(), false),
        ]
    );
    Ok(())
}

/// Regression (todo 33): a change that re-points nothing passes while a source is in use.
///
/// The main listener uses the provider under an `admin` mapping; `mid` changes
/// `max_result_bytes` or `toolsets`, neither of which decides whose tokens count.
#[test]
fn an_unrelated_change_passes_while_the_provider_is_in_use() -> TestResult {
    let toml = mapped("admin", "[mcp.auth.main]\noauth = \"external\"\n");
    let mut bytes = McpOverrides::default();
    bytes.max_result_bytes = Some(4096);
    let mut toolsets = McpOverrides::default();
    toolsets.toolsets = Some(vec!["core".to_owned()]);
    let mut outcomes = Vec::new();
    for change in [&bytes, &toolsets] {
        let (base, _temp, state) = setup(&toml, &[])?;
        outcomes.push(outcome(&plan(&base, &state, &mid(), change)));
    }
    assert_eq!(outcomes, ["ok", "ok"]);
    Ok(())
}

/// Regression (todo 33): the anchored roles are those after the change.
///
/// An override maps `ops` to `admin`; `mid`'s one request empties `role_mappings` and
/// moves the issuer. Nothing is left to hand out `admin`, so it is planned and committed.
#[test]
fn removing_the_higher_mapping_while_re_pointing_passes() -> TestResult {
    let toml = format!("[mcp.auth.main]\noauth = \"external\"\n{PROVIDER}");
    let (base, _temp, state) = setup(&toml, &[])?;
    let mut overrides = McpOverrides::default();
    overrides.auth.oidc.role_mappings =
        Some(vec![RoleMapping::new("ops".to_owned(), "admin".to_owned())]);
    save(&state, overrides)?;
    let mut change = issuer_change()?;
    change.auth.oidc.role_mappings = Some(Vec::new());

    let planned = plan(&base, &state, &mid(), &change);
    assert_eq!(outcome(&planned), "ok");
    commit(
        &state,
        &base.plan_update(&state, &mid(), &change, &|_name| Some(false))?,
    )?;

    let saved = base.effective(&state)?;
    assert!(
        saved.settings().auth.oidc.role_mappings.is_empty(),
        "the mappings stay empty"
    );
    Ok(())
}

/// Regression (todo 33): a mapping to a role that does not exist is skipped.
///
/// It grants nothing, so `mid` may re-point the provider under it. Residual (recorded in
/// the issues notes): a role created later under that name is handed out by the provider
/// without the provider's origin being re-checked; a role created before the commit is
/// refused there (`commit_re_checks_the_anchored_roles`).
#[test]
fn an_unknown_mapping_target_is_skipped() -> TestResult {
    let (base, _temp, state) = setup(
        &mapped("ghost", "[mcp.auth.main]\noauth = \"external\"\n"),
        &[],
    )?;

    let planned = plan(&base, &state, &mid(), &issuer_change()?);

    assert_eq!(outcome(&planned), "ok");
    Ok(())
}
