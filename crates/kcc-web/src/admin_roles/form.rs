//! The custom-role form: its permission checkboxes and the parsing of a submitted form.

extern crate alloc;

use alloc::collections::BTreeSet;

use kcc_app::permissions::Permission;
use kcc_domain::labels;
use kcc_i18n::bundle::MessageKey;

/// Each permission with the form field of its checkbox, in [`Permission::ALL`] order.
const PERMISSIONS: [(Permission, &str); Permission::ALL.len()] = [
    (Permission::Read, "read"),
    (Permission::Write, "write"),
    (Permission::Save, "save"),
    (Permission::Destructive, "destructive"),
    (Permission::Migrate, "migrate"),
    (Permission::RawRci, "raw_rci"),
    (Permission::RevealSecrets, "reveal_secrets"),
    (Permission::ManageRouters, "manage_routers"),
    (Permission::ManageUsers, "manage_users"),
    (Permission::ViewAudit, "view_audit"),
    (Permission::ManageNotifications, "manage_notifications"),
    (Permission::ManageSchedules, "manage_schedules"),
];

/// Each permission with its form field and label, in display order.
pub(super) fn checkboxes() -> impl Iterator<Item = (Permission, &'static str, MessageKey)> {
    PERMISSIONS
        .into_iter()
        .zip(labels::permissions(|_permission| true))
        .map(|((permission, field), label)| (permission, field, label))
}

/// A submitted create or edit form; each ticked permission is sent as its field.
pub(super) struct RoleForm {
    /// Role name.
    name: String,
    /// Router-scope globs separated by commas or spaces.
    scope: String,
    /// The ticked permissions.
    permissions: BTreeSet<Permission>,
    /// Whether a field named no known permission.
    names_unknown: bool,
}

impl RoleForm {
    /// The form of the submitted `pairs`; a field that is neither `name`, `scope` nor a
    /// permission is remembered as an unknown permission, never dropped.
    pub(super) fn parse(pairs: Vec<(String, String)>) -> Self {
        let mut form = Self {
            name: String::new(),
            scope: String::new(),
            permissions: BTreeSet::new(),
            names_unknown: false,
        };
        for (field, value) in pairs {
            match field.as_str() {
                "name" => form.name = value,
                "scope" => form.scope = value,
                other => match PERMISSIONS
                    .iter()
                    .find(|(_permission, name)| *name == other)
                {
                    Some((permission, _name)) => {
                        let _: bool = form.permissions.insert(*permission);
                    }
                    None => form.names_unknown = true,
                },
            }
        }
        form
    }

    /// Role name.
    pub(super) fn name(&self) -> &str {
        &self.name
    }

    /// Router-scope globs as typed.
    pub(super) fn scope_text(&self) -> &str {
        &self.scope
    }

    /// The ticked permissions.
    pub(super) const fn permissions(&self) -> &BTreeSet<Permission> {
        &self.permissions
    }

    /// Whether a field named a permission this server does not know.
    pub(super) const fn names_unknown(&self) -> bool {
        self.names_unknown
    }

    /// The globs in the order typed, without repeats.
    pub(super) fn scope(&self) -> Vec<String> {
        let mut globs: Vec<String> = Vec::new();
        for glob in self
            .scope
            .split(|character: char| character == ',' || character.is_whitespace())
            .filter(|glob| !glob.is_empty())
        {
            if !globs.iter().any(|known| known == glob) {
                globs.push(glob.to_owned());
            }
        }
        globs
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_app::permissions::Permission;

    use super::PERMISSIONS;

    /// W1-11: the checkbox table lists every permission in `Permission::ALL` order, so the
    /// labels zipped onto it belong to their permissions and a new permission can be
    /// granted.
    #[test]
    fn the_checkboxes_cover_every_permission_in_order() {
        assert_eq!(
            PERMISSIONS.map(|(permission, _field)| permission),
            Permission::ALL,
            "the permission column"
        );
        assert_eq!(super::checkboxes().count(), 12, "twelve checkboxes");
    }
}
