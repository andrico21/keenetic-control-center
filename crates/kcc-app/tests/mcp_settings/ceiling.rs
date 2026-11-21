//! The role ceiling of MCP settings changes: resets, router scopes, the mTLS role, the
//! re-check at commit, and the revision limit.

#![expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::missing_errors_doc,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]

use core::error::Error;
use std::fs;

use kcc_app::{
    mcp_settings::{
        Candidate, EnvOverrides, McpBase, SettingsError, commit,
        document::{McpOverrides, McpSettingsDocument},
        keys::KeyPath,
    },
    permissions::{Permission, Role, RolesDocument},
    persist::{StateDoc as _, StateStore},
    settings::{
        Config,
        mcp_schema::{RoleMapping, ScopeMapping},
    },
};
use tempfile::TempDir;

type TestResult = Result<(), Box<dyn Error>>;

/// The acting role `mid`: reads and manages MCP on every router.
fn mid() -> Role {
    Role::new(
        "mid".to_owned(),
        [Permission::Read, Permission::ManageMcp],
        vec!["*".to_owned()],
    )
}

/// A state directory holding the custom `roles`.
fn store_with(roles: &[Role]) -> Result<(TempDir, StateStore), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let state = StateStore::open(&temp.path().join("state"))?;
    let mut document = RolesDocument::default();
    document.roles.extend_from_slice(roles);
    state.write(&document)?;
    Ok((temp, state))
}

/// Writes `overrides` as the state file at `revision`.
fn save(state: &StateStore, overrides: McpOverrides, revision: u64) -> TestResult {
    let mut document = McpSettingsDocument::default();
    document.revision = revision;
    document.overrides = overrides;
    state.write(&document)?;
    Ok(())
}

/// Whether `result` is a `RoleAbove` refusal naming `role`.
fn above<T>(result: &Result<T, SettingsError>, role: &str) -> bool {
    matches!(result, Err(SettingsError::RoleAbove { name }) if name == role)
}

/// Todo 23: resetting a key so that a kcc.toml value naming a role above the actor
/// applies again is refused, for the stdio role, the mTLS role and an OIDC mapping.
#[test]
fn reset_to_a_kcc_toml_role_above_the_actor_is_refused() -> TestResult {
    let mut stdio = McpOverrides::default();
    stdio.stdio_role = Some("viewer".to_owned());
    let mut mtls = McpOverrides::default();
    mtls.auth.mtls.default_role = Some("viewer".to_owned());
    let mut mapping = McpOverrides::default();
    mapping.auth.oidc.role_mappings = Some(vec![RoleMapping::new(
        "ops".to_owned(),
        "viewer".to_owned(),
    )]);
    for (toml, overrides, key) in [
        ("[mcp]\nstdio_role = \"admin\"\n", stdio, KeyPath::StdioRole),
        (
            "[mcp.auth.mtls]\ndefault_role = \"admin\"\n",
            mtls,
            KeyPath::MtlsDefaultRole,
        ),
        (
            "[[mcp.auth.oidc.role_mappings]]\nclaim_value = \"ops\"\nrole = \"admin\"\n",
            mapping,
            KeyPath::OidcRoleMappings,
        ),
    ] {
        let base = McpBase::new(&Config::from_toml_str(toml)?, &EnvOverrides::default());
        let (_temp, state) = store_with(&[mid()])?;
        save(&state, overrides, 1)?;
        let file = state.dir().join(McpSettingsDocument::FILE_NAME);
        let before = fs::read(&file)?;

        let refused = base.reset(&state, &mid(), key);

        assert!(above(&refused, "admin"), "{key}: {refused:?}");
        assert_eq!(fs::read(&file)?, before, "{key}: the state file changed");
    }
    Ok(())
}

/// Todo 23: an actor that holds every permission of the kcc.toml role may reset to it.
#[test]
fn reset_to_a_kcc_toml_role_the_actor_covers_is_planned() -> TestResult {
    let config = Config::from_toml_str("[mcp]\nstdio_role = \"operator\"\n")?;
    let base = McpBase::new(&config, &EnvOverrides::default());
    let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
    let (_temp, state) = store_with(&[])?;
    let mut overrides = McpOverrides::default();
    overrides.stdio_role = Some("viewer".to_owned());
    save(&state, overrides, 1)?;

    commit(&state, &base.reset(&state, &admin, KeyPath::StdioRole)?)?;

    assert_eq!(
        base.effective(&state)?.settings().stdio_role,
        "operator",
        "kcc.toml applies again"
    );
    Ok(())
}

/// Todo 23: an actor with every permission but a narrower router scope cannot name a
/// role that reaches every router, as stdio role, mTLS role or mapping target.
#[test]
fn role_targets_wider_than_the_actor_scope_are_refused() -> TestResult {
    let narrow = Role::new(
        "narrow".to_owned(),
        Permission::ALL,
        vec!["lab-*".to_owned()],
    );
    let wide = Role::new("wide".to_owned(), [Permission::Read], vec!["*".to_owned()]);
    let (_temp, state) = store_with(&[narrow.clone(), wide])?;
    let mut stdio = McpOverrides::default();
    stdio.stdio_role = Some("wide".to_owned());
    let mut mtls = McpOverrides::default();
    mtls.auth.mtls.default_role = Some("wide".to_owned());
    let mut mapping = McpOverrides::default();
    mapping.auth.oidc.scopes = Some(vec![ScopeMapping::new("kcc".to_owned(), "wide".to_owned())]);
    for change in [stdio, mtls, mapping] {
        let refused =
            McpBase::default().plan_update(&state, &narrow, &change, &|_name| Some(false));
        assert!(above(&refused, "wide"), "{change:?}: {refused:?}");
    }
    Ok(())
}

/// Todo 23: a role that grew above the actor between plan and commit is refused at commit.
#[test]
fn commit_refuses_a_role_that_grew_above_the_actor() -> TestResult {
    let target = Role::new(
        "target".to_owned(),
        [Permission::Read],
        vec!["*".to_owned()],
    );
    let (_temp, state) = store_with(&[mid(), target])?;
    let base = McpBase::default();
    let mut change = McpOverrides::default();
    change.stdio_role = Some("target".to_owned());
    let candidate = base.plan_update(&state, &mid(), &change, &|_name| Some(false))?;
    state.update(|roles: &mut RolesDocument| {
        roles.roles.retain(|role| role.name != "target");
        roles.roles.push(Role::new(
            "target".to_owned(),
            [Permission::Read, Permission::Destructive],
            vec!["*".to_owned()],
        ));
    })?;

    let refused = commit(&state, &candidate);

    assert!(above(&refused, "target"), "{refused:?}");
    assert!(
        state.read::<McpSettingsDocument>()?.is_none(),
        "the refused change was written"
    );
    Ok(())
}

/// The custom role `act` with `permissions` on `scope`.
fn act<const N: usize>(permissions: [Permission; N], scope: &str) -> Role {
    Role::new("act".to_owned(), permissions, vec![scope.to_owned()])
}

/// Plans `stdio_role = "tgt"` (Read and Destructive on every router) as `actor`, in a state
/// directory that also holds `act` = Read, `ManageMcp` and Destructive on every router.
fn planned_as(actor: &Role) -> Result<(TempDir, StateStore, Candidate), Box<dyn Error>> {
    let full = act(
        [
            Permission::Read,
            Permission::ManageMcp,
            Permission::Destructive,
        ],
        "*",
    );
    let tgt = Role::new(
        "tgt".to_owned(),
        [Permission::Read, Permission::Destructive],
        vec!["*".to_owned()],
    );
    let (temp, state) = store_with(&[full, tgt])?;
    let mut change = McpOverrides::default();
    change.stdio_role = Some("tgt".to_owned());
    let candidate = McpBase::default().plan_update(&state, actor, &change, &|_name| Some(false))?;
    Ok((temp, state, candidate))
}

/// Todo 23: the acting role demoted, narrowed, deleted or stripped of `ManageMcp` between
/// plan and commit is checked as it is now, so the commit is refused and nothing written.
#[test]
fn commit_checks_the_actor_as_it_is_now() -> TestResult {
    let full = [
        Permission::Read,
        Permission::ManageMcp,
        Permission::Destructive,
    ];
    let mut outcomes = Vec::new();
    let mut expected = Vec::new();
    for (case, now, refusal) in [
        (
            "lost Destructive",
            Some(act([Permission::Read, Permission::ManageMcp], "*")),
            "RoleAbove tgt",
        ),
        ("scope narrowed", Some(act(full, "lab-*")), "RoleAbove tgt"),
        ("deleted", None, "ActorRevoked act"),
        (
            "lost ManageMcp",
            Some(act([Permission::Read, Permission::Destructive], "*")),
            "ActorRevoked act",
        ),
    ] {
        let (_temp, state, candidate) = planned_as(&act(full, "*"))?;
        state.update(|roles: &mut RolesDocument| {
            roles.roles.retain(|role| role.name != "act");
            roles.roles.extend(now);
        })?;

        let refused = commit(&state, &candidate);

        let matched = match &refused {
            Err(SettingsError::RoleAbove { name }) => format!("RoleAbove {name}"),
            Err(SettingsError::ActorRevoked { name }) => format!("ActorRevoked {name}"),
            other => format!("{other:?}"),
        };
        let written = state.read::<McpSettingsDocument>()?.is_some();
        outcomes.push((case, matched, written));
        expected.push((case, refusal.to_owned(), false));
    }
    assert_eq!(outcomes, expected);
    Ok(())
}

/// Todo 23: an unchanged custom actor and the built-in `admin` both commit.
#[test]
fn commit_by_an_unchanged_actor_is_written() -> TestResult {
    let full = act(
        [
            Permission::Read,
            Permission::ManageMcp,
            Permission::Destructive,
        ],
        "*",
    );
    let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
    for actor in [full, admin] {
        let (_temp, state, candidate) = planned_as(&actor)?;

        commit(&state, &candidate)?;

        assert_eq!(
            McpBase::default().effective(&state)?.settings().stdio_role,
            "tgt",
            "{}",
            actor.name
        );
    }
    Ok(())
}

/// Todo 23: a state file at the largest revision takes no further change.
#[test]
fn a_change_on_the_largest_revision_is_refused() -> TestResult {
    let admin = Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]);
    let (_temp, state) = store_with(&[])?;
    save(&state, McpOverrides::default(), u64::MAX)?;
    let mut change = McpOverrides::default();
    change.max_result_bytes = Some(1024);

    let refused = McpBase::default().plan_update(&state, &admin, &change, &|_name| Some(false));

    assert!(
        matches!(refused, Err(SettingsError::RevisionExhausted)),
        "{refused:?}"
    );
    Ok(())
}
