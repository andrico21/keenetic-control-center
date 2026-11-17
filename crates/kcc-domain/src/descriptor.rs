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

/// Builds metadata for a read that needs `Read`.
pub(crate) const fn read(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    operation(name, catalog_path, Risk::Read, Permission::Read)
}

/// Builds metadata for an ordinary write that needs `Write`.
pub(crate) const fn write(name: &'static str, catalog_path: &'static str) -> OperationDescriptor {
    operation(name, catalog_path, Risk::Write, Permission::Write)
}

/// Builds metadata for an operation at `risk` that needs `Read` for a read and `Write`
/// otherwise.
pub(crate) const fn by_risk(
    name: &'static str,
    catalog_path: &'static str,
    risk: Risk,
) -> OperationDescriptor {
    let permission = if matches!(risk, Risk::Read) {
        Permission::Read
    } else {
        Permission::Write
    };
    operation(name, catalog_path, risk, permission)
}
