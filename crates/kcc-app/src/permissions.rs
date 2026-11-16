//! Permission and role definitions shared by the web, MCP and CLI front-ends.

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use rmcp_server_kit::rbac::{RbacConfig, RoleConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::persist::{Migration, StateDoc, StateError, StateStore};

pub mod assignment;

/// A capability that can be granted to a role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Permission {
    /// Read router state.
    Read,
    /// Change running configuration.
    Write,
    /// Persist running configuration.
    Save,
    /// Perform destructive operations.
    Destructive,
    /// Migrate configuration between routers.
    Migrate,
    /// Send catalog-validated raw RCI requests.
    RawRci,
    /// Reveal stored secrets to an authorized caller.
    RevealSecrets,
    /// Create, update and remove router profiles.
    ManageRouters,
    /// Create, update and remove users and credentials.
    ManageUsers,
    /// View the audit log.
    ViewAudit,
}

impl Permission {
    /// Every permission, used by the built-in administrator role.
    pub const ALL: [Self; 10] = [
        Self::Read,
        Self::Write,
        Self::Save,
        Self::Destructive,
        Self::Migrate,
        Self::RawRci,
        Self::RevealSecrets,
        Self::ManageRouters,
        Self::ManageUsers,
        Self::ViewAudit,
    ];
}

/// A named set of permissions and router-name glob scopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Role {
    /// Role name used by accounts and API keys.
    pub name: String,
    /// Capabilities granted to the role.
    pub permissions: BTreeSet<Permission>,
    /// Router-name globs, interpreted by rmcp-server-kit's host matcher.
    pub router_scope: Vec<String>,
}

impl Role {
    /// Builds a role from a permission iterator and router scope.
    #[inline]
    #[must_use]
    pub fn new<I>(name: String, permissions: I, router_scope: Vec<String>) -> Self
    where
        I: IntoIterator<Item = Permission>,
    {
        Self {
            name,
            permissions: permissions.into_iter().collect(),
            router_scope,
        }
    }

    /// Whether this role grants `permission`.
    #[inline]
    #[must_use]
    pub fn grants(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Whether this role holds every permission of `target` and covers its whole router
    /// scope, so granting or managing `target` cannot raise anyone above this role.
    #[inline]
    #[must_use]
    pub fn dominates(&self, target: &Self) -> bool {
        let everything = [String::from("*")];
        let scope = if target.router_scope.is_empty() {
            &everything[..]
        } else {
            &*target.router_scope
        };
        target
            .permissions
            .iter()
            .all(|permission| self.grants(*permission))
            && scope.iter().all(|glob| self.covers(glob))
    }

    /// Whether every router `glob` can match is matched by this role's scope: a
    /// conservative check on the kit's `*`-only globs (equal globs, `*`, or a literal
    /// prefix followed by `*`). An empty scope covers every router.
    #[inline]
    #[must_use]
    pub fn covers(&self, glob: &str) -> bool {
        self.router_scope.is_empty()
            || self.router_scope.iter().any(|outer| {
                outer == "*"
                    || outer == glob
                    || outer
                        .strip_suffix('*')
                        .is_some_and(|prefix| !prefix.contains('*') && glob.starts_with(prefix))
            })
    }
}

/// Custom roles persisted in `roles.json`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RolesDocument {
    /// Custom role definitions.
    pub roles: Vec<Role>,
}

impl StateDoc for RolesDocument {
    const FILE_NAME: &'static str = "roles.json";
    const SCHEMA: u32 = 1;
    const MIGRATIONS: &'static [Migration] = &[];
}

/// A tool and the permission needed to invoke it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ToolSpec {
    /// MCP tool name.
    pub name: String,
    /// Permission required by this tool.
    pub permission: Permission,
    /// Tool annotations passed through by the registry owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
}

impl ToolSpec {
    /// Defines a tool permission requirement.
    #[inline]
    #[must_use]
    pub const fn new(name: String, permission: Permission, annotations: Option<Value>) -> Self {
        Self {
            name,
            permission,
            annotations,
        }
    }
}

/// Permission model errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PermissionError {
    /// State storage failed.
    #[error(transparent)]
    State(#[from] StateError),
    /// A custom role tried to replace a built-in role.
    #[error("custom role cannot replace built-in role {name:?}")]
    BuiltInOverride {
        /// Rejected role name.
        name: String,
    },
    /// A role name occurred more than once.
    #[error("duplicate role {name:?}")]
    DuplicateRole {
        /// Repeated role name.
        name: String,
    },
    /// A role has no router scope.
    #[error("role {name:?} must have at least one router scope glob")]
    EmptyRouterScope {
        /// Invalid role name.
        name: String,
    },
}

/// Returns the three immutable built-in roles.
#[inline]
#[must_use]
pub fn built_in_roles() -> [Role; 3] {
    [
        Role::new(
            "viewer".to_owned(),
            [Permission::Read],
            vec!["*".to_owned()],
        ),
        Role::new(
            "operator".to_owned(),
            [
                Permission::Read,
                Permission::Write,
                Permission::Save,
                Permission::Migrate,
            ],
            vec!["*".to_owned()],
        ),
        Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()]),
    ]
}

/// Loads built-in and custom roles, rejecting ambiguous definitions.
///
/// # Errors
///
/// Returns a state error for an unreadable document or a validation error for
/// duplicate names, built-in overrides, or empty scopes.
#[inline]
pub fn load_roles(store: &StateStore) -> Result<Vec<Role>, PermissionError> {
    let built_ins = built_in_roles();
    let mut roles: BTreeMap<String, Role> = built_ins
        .into_iter()
        .map(|role| (role.name.clone(), role))
        .collect();
    let custom = store.read::<RolesDocument>()?.unwrap_or_default();
    let built_in_names = ["viewer", "operator", "admin"];
    for role in custom.roles {
        if built_in_names.contains(&role.name.as_str()) {
            return Err(PermissionError::BuiltInOverride { name: role.name });
        }
        if role.router_scope.is_empty() {
            return Err(PermissionError::EmptyRouterScope { name: role.name });
        }
        let name = role.name.clone();
        if roles.insert(name.clone(), role).is_some() {
            return Err(PermissionError::DuplicateRole { name });
        }
    }
    Ok(roles.into_values().collect())
}

/// Converts application roles and tools into rmcp-server-kit's RBAC config.
///
/// Each role receives exactly the tools whose permission it grants; router
/// scopes become kit host globs unchanged.
#[inline]
#[must_use]
pub fn rbac_config(roles: &[Role], tools: &[ToolSpec]) -> RbacConfig {
    let role_configs = roles
        .iter()
        .map(|role| {
            let allow = tools
                .iter()
                .filter(|tool| role.grants(tool.permission))
                .map(|tool| tool.name.clone())
                .collect();
            RoleConfig::new(role.name.clone(), allow, role.router_scope.clone())
        })
        .collect();
    RbacConfig::with_roles(role_configs)
}
