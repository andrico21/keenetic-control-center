//! Construction of ordinary domain operation metadata.

use kcc_app::permissions::Permission;
use kcc_catalog::Risk;

use crate::OperationDescriptor;

/// Builds metadata for an operation that does not persist implicitly.
pub(crate) const fn operation(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
    permission: Permission,
) -> OperationDescriptor {
    OperationDescriptor {
        name,
        catalog_path,
        risk,
        permission,
        persists_immediately: false,
    }
}
