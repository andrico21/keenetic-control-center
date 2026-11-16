//! `apikey create` and `user add` grant only roles the CLI principal dominates.

use core::error::Error;
use std::fs;

use kcc_app::{
    accounts::UsersDocument,
    api_keys::ApiKeysDocument,
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};

use super::support::{Env, TestResult};

/// One CLI principal setup: its role, the role's scope and the `[cli] router_scope`.
struct Principal {
    /// The custom role's router scope.
    role_scope: &'static [&'static str],
    /// The `[cli] router_scope` line, empty for none.
    cli_scope: &'static str,
}

/// An environment whose `[cli] role` is `keymaster`, a custom role holding `ManageUsers`
/// and Read with `principal`'s scopes.
fn keymaster(principal: &Principal) -> Result<Env, Box<dyn Error>> {
    let env = Env::new(&format!(
        "[cli]\nrole = \"keymaster\"\n{}\n",
        principal.cli_scope
    ))?;
    let mut roles = RolesDocument::default();
    roles.roles.push(Role::new(
        "keymaster".to_owned(),
        [Permission::ManageUsers, Permission::Read],
        principal
            .role_scope
            .iter()
            .map(|glob| (*glob).to_owned())
            .collect(),
    ));
    StateStore::open(&env.state_dir())?.write(&roles)?;
    Ok(env)
}

/// F-06: the CLI refuses to grant a role the principal does not dominate, like the Web.
///
/// A `ManageUsers` role without the other permissions, or covering fewer routers (by its
/// own scope or by `[cli] router_scope`), cannot mint an `admin` or `viewer` key or
/// account: exit 10 (policy), nothing stored, the refusal audited as `forbidden`. The
/// same principal may still grant its own role.
#[test]
fn cli_grants_only_dominated_roles() -> TestResult {
    let cases = [
        (
            Principal {
                role_scope: &["*"],
                cli_scope: "",
            },
            "admin",
        ),
        (
            Principal {
                role_scope: &["lab-*"],
                cli_scope: "",
            },
            "viewer",
        ),
        (
            Principal {
                role_scope: &["*"],
                cli_scope: "router_scope = [\"lab-*\"]",
            },
            "viewer",
        ),
    ];
    for (principal, target) in &cases {
        let env = keymaster(principal)?;
        let password = env.write("bob.password", &"bob-pass-".repeat(2))?;
        let key = env.kcc(&["apikey", "create", "ci", "--role", target])?;
        assert_eq!(key.code, 10_i32, "{target}: {key:?}");
        let user = env.kcc(&[
            "--password-file",
            password.to_str().ok_or("non-UTF-8 path")?,
            "user",
            "add",
            "bob",
            "--role",
            target,
        ])?;
        assert_eq!(user.code, 10_i32, "{target}: {user:?}");
        let store = StateStore::open(&env.state_dir())?;
        let keys = store.read::<ApiKeysDocument>()?.unwrap_or_default().keys;
        let users = store.read::<UsersDocument>()?.unwrap_or_default().users;
        assert!(
            keys.is_empty() && users.is_empty(),
            "{target}: a grant was stored"
        );
        let audit = fs::read_to_string(env.state_dir().join("audit.jsonl"))?;
        let refused = audit
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|entry| {
                entry.get("outcome").and_then(serde_json::Value::as_str) == Some("forbidden")
            })
            .filter_map(|entry| {
                entry
                    .get("action")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .collect::<Vec<_>>();
        assert_eq!(refused, ["cli.apikey_create", "cli.user_add"], "{target}");
        if principal.cli_scope.is_empty() {
            let own = env.kcc(&["apikey", "create", "own", "--role", "keymaster"])?;
            assert_eq!(own.code, 0_i32, "{own:?}");
        }
    }
    Ok(())
}
