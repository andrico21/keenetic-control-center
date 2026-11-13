//! Who may do what on a router: the permissions a request needs, the controls a page
//! shows, and the re-check every handler makes before it acts.
//!
//! A page hides what the role may not do through [`Controls`]; the handler checks again
//! with [`allowed`] and answers 403, because a hidden button is not a permission check.

use kcc_app::{
    permissions::{Permission, Role},
    registry,
};
use kcc_catalog::{Catalog, Risk};
use kcc_domain::{OperationDescriptor, configuration::SafetyNet};

use crate::authz::CurrentUser;

/// The permissions a raw command of catalog `risk` needs on its router: `Read` for a
/// read, otherwise what [`SafetyNet::required`] asks of a `RawRci` change.
pub(crate) fn command_permissions(risk: Risk) -> Vec<Permission> {
    match risk {
        Risk::Read => vec![Permission::Read],
        Risk::Write | Risk::Management | Risk::Destructive | _ => {
            SafetyNet::required(Permission::RawRci, risk)
        }
    }
}

/// Whether `user` holds every one of `permissions` on `router`.
pub(crate) fn allowed(user: &CurrentUser, router: &str, permissions: &[Permission]) -> bool {
    permissions
        .iter()
        .all(|permission| registry::authorize(user.role(), *permission, router).is_ok())
}

/// What one user may do on one router: the permissions their role holds there and the
/// operations of a page's domain they may run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Controls {
    /// Permissions held on the router, in [`Permission::ALL`] order.
    held: Vec<Permission>,
    /// Names of the domain operations the role may run and the router's catalog has.
    operations: Vec<&'static str>,
}

impl Controls {
    /// The controls `role` may use on `router`, its scope included.
    pub(crate) fn new(role: &Role, router: &str) -> Self {
        Self {
            held: Permission::ALL
                .into_iter()
                .filter(|permission| registry::authorize(role, *permission, router).is_ok())
                .collect(),
            operations: Vec::new(),
        }
    }

    /// Adds the `operations` the role may run and, when the router's `catalog` is known,
    /// that it has: a page shows a control only for those.
    pub(crate) fn with_operations(
        mut self,
        operations: &'static [OperationDescriptor],
        catalog: Option<&Catalog>,
    ) -> Self {
        let held = self.held.clone();
        self.operations = operations
            .iter()
            .filter(|operation| catalog.is_none_or(|known| operation.available(known)))
            .filter(|operation| {
                SafetyNet::required(operation.permission, operation.risk)
                    .iter()
                    .all(|permission| held.contains(permission))
            })
            .map(|operation| operation.name)
            .collect();
        self
    }

    /// Whether the role may run the operation `name` of the page's domain.
    pub(crate) fn allows(&self, name: &str) -> bool {
        self.operations.contains(&name)
    }

    /// Whether the role holds `permission` on the router.
    pub(crate) fn holds(&self, permission: Permission) -> bool {
        self.held.contains(&permission)
    }

    /// Whether the role holds every one of `permissions` on the router.
    pub(crate) fn permits(&self, permissions: &[Permission]) -> bool {
        permissions.iter().all(|permission| self.holds(*permission))
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role, built_in_roles};
    use kcc_catalog::Risk;

    use super::{Controls, command_permissions};

    #[test]
    fn controls_follow_the_role_and_its_scope() {
        let [viewer, operator, admin] = built_in_roles();
        let viewing = Controls::new(&viewer, "home");
        assert!(viewing.holds(Permission::Read), "viewer reads");
        assert!(!viewing.holds(Permission::Write), "viewer does not write");
        let operating = Controls::new(&operator, "home");
        assert!(
            operating.permits(&[Permission::Read, Permission::Write, Permission::Save]),
            "operator changes and saves"
        );
        assert!(
            !operating.permits(&command_permissions(Risk::Management)),
            "operator runs no raw management command"
        );
        assert!(
            Controls::new(&admin, "home").permits(&command_permissions(Risk::Destructive)),
            "admin may"
        );
        let lab = Role::new("lab".to_owned(), Permission::ALL, vec!["lab-*".to_owned()]);
        assert_eq!(
            Controls::new(&lab, "home"),
            Controls::default(),
            "outside the scope nothing is held"
        );
        assert!(
            Controls::new(&lab, "lab-1").holds(Permission::Destructive),
            "in scope"
        );
    }
}
