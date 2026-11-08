//! The live role set shared by the Web UI, the MCP handlers and the reload paths.
//!
//! Every front end that authorizes against application roles reads them from one
//! [`RoleSource`]; a role edit in the Web UI or a SIGHUP reload replaces the set once and
//! the next check anywhere sees it, so a reduced role never outlives its edit.

extern crate alloc;

use alloc::sync::Arc;
use core::fmt;
use std::sync::{PoisonError, RwLock};

use crate::permissions::Role;

/// A cheaply cloned handle to the current built-in and custom roles.
#[derive(Clone)]
#[non_exhaustive]
pub struct RoleSource {
    /// The current role set; replaced whole.
    roles: Arc<RwLock<Arc<[Role]>>>,
}

impl fmt::Debug for RoleSource {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoleSource")
            .field("roles", &self.current())
            .finish()
    }
}

impl RoleSource {
    /// A source holding `roles`.
    #[inline]
    #[must_use]
    pub fn new(roles: Vec<Role>) -> Self {
        Self {
            roles: Arc::new(RwLock::new(roles.into())),
        }
    }

    /// The current roles.
    #[inline]
    #[must_use]
    pub fn current(&self) -> Arc<[Role]> {
        Arc::clone(&self.roles.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// The current definition of the role `name`.
    #[inline]
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Role> {
        self.current()
            .iter()
            .find(|role| role.name == name)
            .cloned()
    }

    /// Replaces every role; readers see the new set from their next check on.
    #[inline]
    pub fn replace(&self, roles: Vec<Role>) {
        *self.roles.write().unwrap_or_else(PoisonError::into_inner) = roles.into();
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::RoleSource;
    use crate::permissions::{Permission, Role};

    #[test]
    fn a_replacement_reaches_every_clone() {
        let source = RoleSource::new(vec![Role::new(
            "ops".to_owned(),
            [Permission::Read, Permission::ManageUsers],
            vec!["*".to_owned()],
        )]);
        let reader = source.clone();
        source.replace(vec![Role::new(
            "ops".to_owned(),
            [Permission::Read],
            vec!["*".to_owned()],
        )]);
        let ops = reader.find("ops");
        assert!(
            ops.is_some_and(|role| !role.grants(Permission::ManageUsers)),
            "the clone sees the reduced role"
        );
        assert!(reader.find("gone").is_none(), "unknown role");
    }
}
