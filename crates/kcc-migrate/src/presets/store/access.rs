//! Who may read, replace and delete a stored preset.

use kcc_app::{
    permissions::{Permission, Role},
    registry::authorize,
};

use super::PresetError;

/// Validates a file-safe preset id.
///
/// # Errors
///
/// Returns [`PresetError::InvalidId`] for an empty, oversized, or unsafe id.
pub(super) fn validate_id(id: &str) -> Result<(), PresetError> {
    let valid = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'));
    valid.then_some(()).ok_or(PresetError::InvalidId)
}

/// Requires an application permission without consulting a router scope.
///
/// # Errors
///
/// Returns [`PresetError::Forbidden`] when the role lacks the permission.
pub(super) fn require_permission(role: &Role, permission: Permission) -> Result<(), PresetError> {
    role.grants(permission)
        .then_some(())
        .ok_or(PresetError::Forbidden)
}

/// Authorizes migration access to an optional registered source router.
///
/// # Errors
///
/// Returns [`PresetError::Forbidden`] when permission or source scope is absent.
pub(super) fn authorize_source(
    role: &Role,
    source_router: Option<&str>,
) -> Result<(), PresetError> {
    require_permission(role, Permission::Migrate)?;
    source_router.map_or(Ok(()), |router_id| {
        authorize(role, Permission::Migrate, router_id).map_err(|_error| PresetError::Forbidden)
    })
}

/// Authorizes migration access to a record whose source router is unknown: only a role
/// whose scope covers every router may act on it.
///
/// # Errors
///
/// Returns [`PresetError::Forbidden`] without `Migrate` or for a scoped role.
pub(super) fn authorize_any_source(role: &Role) -> Result<(), PresetError> {
    require_permission(role, Permission::Migrate)?;
    let unscoped = role.router_scope.is_empty() || role.router_scope.iter().any(|glob| glob == "*");
    unscoped.then_some(()).ok_or(PresetError::Forbidden)
}

/// Reports whether list output may expose a preset from the source router.
pub(super) fn source_allowed(role: &Role, source_router: Option<&str>) -> bool {
    role.grants(Permission::Read)
        && source_router
            .is_none_or(|router_id| authorize(role, Permission::Read, router_id).is_ok())
}
