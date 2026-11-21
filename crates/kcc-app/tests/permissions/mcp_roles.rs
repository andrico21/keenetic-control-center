//! The `ManageMcp` permission, the reserved `kcc-account` role, and roles held by the MCP
//! settings.

#![expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]

use core::error::Error;

use kcc_app::{
    mcp_settings::{EnvOverrides, McpBase, commit, document::McpOverrides},
    permissions::{
        KCC_ACCOUNT_ROLE, Permission, PermissionError, Role, RolesDocument, ToolSpec,
        assignment::remove_unheld, built_in_roles, load_roles, rbac_config,
    },
    persist::StateStore,
    settings::{Config, ConfigError},
};
use rmcp_server_kit::rbac::{RbacDecision, RbacPolicy};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

/// A state directory holding the custom role `lab-ops`.
fn with_lab_ops() -> Result<(TempDir, StateStore), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let mut roles = RolesDocument::default();
    roles.roles.push(Role::new(
        "lab-ops".to_owned(),
        [Permission::Read],
        vec!["lab-*".to_owned()],
    ));
    state.write(&roles)?;
    Ok((temp, state))
}

/// Tries to delete `lab-ops` the way the Roles page does, holding the roles lock.
fn delete_lab_ops(state: &StateStore, base: &McpBase) -> Result<bool, Box<dyn Error>> {
    state.update(|roles: &mut RolesDocument| {
        let held = base.held_roles(state)?;
        Ok(remove_unheld(state, roles, "lab-ops", &held)?)
    })?
}

/// Whether `lab-ops` still exists.
fn lab_ops_exists(state: &StateStore) -> Result<bool, Box<dyn Error>> {
    Ok(load_roles(state)?.iter().any(|role| role.name == "lab-ops"))
}

/// Todo 23: thirteen permissions; only the built-in admin holds `ManageMcp`.
#[test]
fn manage_mcp_is_the_thirteenth_permission_and_admin_only() -> TestResult {
    assert_eq!(Permission::ALL.len(), 13, "permission count");
    for role in built_in_roles() {
        assert_eq!(
            role.grants(Permission::ManageMcp),
            role.name == "admin",
            "{}",
            role.name
        );
    }
    assert_eq!(
        serde_json::to_string(&Permission::ManageMcp)?,
        "\"manage_mcp\"",
        "serde name"
    );
    Ok(())
}

/// Todo 23: no custom role may take the reserved name, and the RBAC config always has it
/// with every tool on every router.
#[test]
fn kcc_account_is_reserved_and_always_in_the_rbac_config() -> TestResult {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let mut roles = RolesDocument::default();
    roles.roles.push(Role::new(
        KCC_ACCOUNT_ROLE.to_owned(),
        [Permission::Read],
        vec!["*".to_owned()],
    ));
    state.write(&roles)?;
    let refused = load_roles(&state);
    assert!(
        matches!(&refused, Err(PermissionError::Reserved { name }) if name == KCC_ACCOUNT_ROLE),
        "{refused:?}"
    );

    let tools = [
        ToolSpec::new("router_show".to_owned(), Permission::Read, None),
        ToolSpec::new("router_reset".to_owned(), Permission::Destructive, None),
    ];
    let policy = RbacPolicy::new(&rbac_config(&built_in_roles(), &tools));
    for tool in ["router_show", "router_reset"] {
        assert_eq!(
            policy.check(KCC_ACCOUNT_ROLE, tool, "any-router"),
            RbacDecision::Allow,
            "{tool}"
        );
    }
    Ok(())
}

/// Todo 23: kcc.toml cannot name the reserved role as an MCP role target, and the
/// refusal names the field that does.
#[test]
fn kcc_account_is_refused_as_a_kcc_toml_role_target() -> TestResult {
    for (text, expected) in [
        ("[mcp]\nstdio_role = \"kcc-account\"\n", "mcp.stdio_role"),
        (
            "[mcp.auth.mtls]\ndefault_role = \"kcc-account\"\n",
            "mcp.auth.mtls.default_role",
        ),
        (
            "[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"ops\"\nrole = \"kcc-account\"\n",
            "mcp.auth.oidc.role_mappings",
        ),
        (
            "[[mcp.auth.oidc.scopes]]\nscope = \"kcc.ops\"\nrole = \"kcc-account\"\n",
            "mcp.auth.oidc.scopes",
        ),
    ] {
        let refused = Config::from_toml_str(text)?.validate();
        assert!(
            matches!(&refused, Err(ConfigError::Invalid { field, reason: _ }) if field == expected),
            "{text}: {refused:?}"
        );
    }
    Ok(())
}

/// Todo 23: a role the environment names as the stdio role cannot be deleted.
#[test]
fn role_named_by_the_environment_is_kept() -> TestResult {
    let (_temp, state) = with_lab_ops()?;
    let mut config = Config::default();
    let reports = config.apply_kcc_env_overrides_with(|var| {
        Ok((var == "KCC_MCP_STDIO_ROLE").then(|| "lab-ops".to_owned()))
    })?;
    let base = McpBase::new(&config, &EnvOverrides::from_reports(&reports));

    assert!(!delete_lab_ops(&state, &base)?, "deletion was not refused");
    assert!(lab_ops_exists(&state)?, "the role is gone");
    Ok(())
}

/// Todo 23: a role the Web settings name as the stdio role cannot be deleted.
#[test]
fn role_named_as_stdio_role_in_the_state_file_is_kept() -> TestResult {
    let (_temp, state) = with_lab_ops()?;
    let base = McpBase::default();
    let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
    let mut change = McpOverrides::default();
    change.stdio_role = Some("lab-ops".to_owned());
    commit(
        &state,
        &base.plan_update(&state, &admin, &change, &|_name| Some(false))?,
    )?;

    assert!(!delete_lab_ops(&state, &base)?, "deletion was not refused");
    assert!(lab_ops_exists(&state)?, "the role is gone");
    Ok(())
}

/// Todo 23: a role kcc.toml names as the stdio role or an OIDC mapping target cannot be
/// deleted; an unnamed one can.
#[test]
fn role_named_in_kcc_toml_is_kept() -> TestResult {
    for text in [
        "[mcp]\nstdio_role = \"lab-ops\"\n",
        "[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"ops\"\nrole = \"lab-ops\"\n",
        "[[mcp.auth.oidc.scopes]]\nscope = \"kcc.ops\"\nrole = \"lab-ops\"\n",
    ] {
        let (_temp, state) = with_lab_ops()?;
        let base = McpBase::new(&Config::from_toml_str(text)?, &EnvOverrides::default());
        assert!(!delete_lab_ops(&state, &base)?, "{text}: not refused");
        assert!(lab_ops_exists(&state)?, "{text}: the role is gone");
    }
    let (_temp, state) = with_lab_ops()?;
    assert!(
        delete_lab_ops(&state, &McpBase::default())?,
        "an unnamed role is deleted"
    );
    assert!(!lab_ops_exists(&state)?, "the role is still there");
    Ok(())
}
