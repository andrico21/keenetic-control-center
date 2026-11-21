//! The localized names of application permissions, as the Roles page shows them.

use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::MessageKey, keys};

/// The name of each permission of [`Permission::ALL`], in the same order; a permission
/// added there without a name here does not compile.
const NAMES: [MessageKey; Permission::ALL.len()] = [
    keys::WEB_ADMIN_PERMISSION_READ,
    keys::WEB_ADMIN_PERMISSION_WRITE,
    keys::WEB_ADMIN_PERMISSION_SAVE,
    keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE,
    keys::WEB_ADMIN_PERMISSION_MIGRATE,
    keys::WEB_ADMIN_PERMISSION_RAW_RCI,
    keys::WEB_ADMIN_PERMISSION_REVEAL_SECRETS,
    keys::WEB_ADMIN_PERMISSION_MANAGE_ROUTERS,
    keys::WEB_ADMIN_PERMISSION_MANAGE_USERS,
    keys::WEB_ADMIN_PERMISSION_VIEW_AUDIT,
    keys::WEB_ADMIN_PERMISSION_MANAGE_NOTIFICATIONS,
    keys::WEB_ADMIN_PERMISSION_MANAGE_SCHEDULES,
    keys::WEB_ADMIN_PERMISSION_MANAGE_MCP,
];

/// The message keys naming the permissions `held` selects, in [`Permission::ALL`] order.
#[inline]
pub fn permissions<F>(held: F) -> impl Iterator<Item = MessageKey>
where
    F: Fn(Permission) -> bool,
{
    Permission::ALL
        .into_iter()
        .zip(NAMES)
        .filter(move |(permission, _name)| held(*permission))
        .map(|(_permission, name)| name)
}
