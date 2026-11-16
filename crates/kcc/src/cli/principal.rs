//! The CLI principal: `cli:<OS username>` acting with the `[cli]` role and scope.

use std::env;

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::{Permission, Role},
    registry::scope_matches,
    settings::CliConfig,
};

use super::exit::{Exit, Failure, Outcome, denied};

/// Longest OS user name kept in the identity.
const MAX_USER: usize = 64;

/// Who the CLI acts as.
#[derive(Debug, Clone)]
pub(crate) struct Principal {
    /// Identity `cli:<OS username>`.
    id: String,
    /// The `[cli] role` with its own router scope.
    role: Role,
    /// The `[cli] router_scope` globs; empty means every router the role may touch.
    scope: Vec<String>,
}

impl Principal {
    /// Resolves the configured role among the built-in and custom `roles`.
    ///
    /// # Errors
    ///
    /// Returns a generic failure when `[cli] role` names no role.
    pub(crate) fn resolve(config: &CliConfig, roles: &[Role]) -> Outcome<Self> {
        let role = roles
            .iter()
            .find(|role| role.name == config.role)
            .cloned()
            .ok_or_else(|| {
                Failure::text(
                    Exit::Generic,
                    &format!("[cli] role {:?} does not exist", config.role),
                )
            })?;
        Ok(Self {
            id: format!("cli:{}", os_username()),
            role,
            scope: config.router_scope.clone(),
        })
    }

    /// The audit actor of this invocation.
    pub(crate) fn actor(&self) -> Actor {
        Actor::new(ActorKind::Cli, self.id.clone())
    }

    /// Account name associated with this operating-system principal.
    pub(crate) fn account_name(&self) -> &str {
        self.id.strip_prefix("cli:").unwrap_or("unknown")
    }

    /// Configured application role of this principal.
    pub(crate) const fn role(&self) -> &Role {
        &self.role
    }

    /// Whether `router` lies inside both the role's and the CLI's router scope.
    pub(crate) fn sees(&self, router: &str) -> bool {
        scope_matches(&self.role.router_scope, router) && scope_matches(&self.scope, router)
    }

    /// Whether the role grants `permission` at all (for actions not tied to a router).
    pub(crate) fn grants(&self, permission: Permission) -> bool {
        self.role.grants(permission)
    }

    /// The authority this invocation grants roles with: the role's permissions over the
    /// routers that both the role's scope and `[cli] router_scope` cover.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal (exit 10) when the two scopes share no router.
    pub(crate) fn authority(&self) -> Outcome<Role> {
        if self.scope.is_empty() {
            return Ok(self.role.clone());
        }
        let cli = Role::new(String::new(), [], self.scope.clone());
        let scope = self
            .scope
            .iter()
            .filter(|glob| self.role.covers(glob))
            .chain(
                self.role
                    .router_scope
                    .iter()
                    .filter(|glob| cli.covers(glob)),
            )
            .cloned()
            .collect::<Vec<_>>();
        if scope.is_empty() {
            return Err(denied("-"));
        }
        Ok(Role::new(
            self.role.name.clone(),
            self.role.permissions.iter().copied(),
            scope,
        ))
    }

    /// Requires `permission` without a router.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal (exit 10).
    pub(crate) fn require(&self, permission: Permission) -> Outcome {
        if self.grants(permission) {
            Ok(())
        } else {
            Err(denied("-"))
        }
    }

    /// Checks every permission on every router and returns the role narrowed to exactly
    /// those routers, which the `kcc-app` services check again.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal (exit 10) naming the first router refused.
    pub(crate) fn authorize(&self, permissions: &[Permission], routers: &[&str]) -> Outcome<Role> {
        for router in routers {
            let held = permissions
                .iter()
                .all(|permission| self.role.grants(*permission));
            if !held || !self.sees(router) {
                return Err(denied(router));
            }
        }
        Ok(Role::new(
            self.role.name.clone(),
            self.role.permissions.iter().copied(),
            routers.iter().map(|router| (*router).to_owned()).collect(),
        ))
    }
}

/// The OS user name from the environment, reduced to `[A-Za-z0-9._-]`.
fn os_username() -> String {
    let raw = ["USER", "USERNAME", "LOGNAME"]
        .into_iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_else(|| "unknown".to_owned());
    let cleaned = raw
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || "._-".contains(*character))
        .take(MAX_USER)
        .collect::<String>();
    if cleaned.is_empty() {
        "unknown".to_owned()
    } else {
        cleaned
    }
}
