//! Roles as the administration pages show and guard them: built-in roles, display order
//! and labels, the role select, and who may manage a holder of a role.

use kcc_app::permissions::{Permission, Role, built_in_roles};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{WebState, authz::CurrentUser};

/// The labels of the built-in roles, in [`built_in_roles`] order.
const BUILT_IN_LABELS: [MessageKey; 3] = [
    keys::WEB_ADMIN_ROLE_VIEWER,
    keys::WEB_ADMIN_ROLE_OPERATOR,
    keys::WEB_ADMIN_ROLE_ADMIN,
];

/// Whether `name` is one of the three immutable built-in roles.
pub(crate) fn is_built_in(name: &str) -> bool {
    built_in_roles().iter().any(|role| role.name == name)
}

/// `roles` in display order: built-in roles in rising privilege, then custom roles by
/// name.
pub(crate) fn ordered(roles: &[Role]) -> Vec<Role> {
    let built_in = built_in_roles();
    let rank = |role: &Role| {
        built_in
            .iter()
            .position(|candidate| candidate.name == role.name)
            .unwrap_or(built_in.len())
    };
    let mut sorted = roles.to_vec();
    sorted.sort_by(|left, right| {
        rank(left)
            .cmp(&rank(right))
            .then_with(|| left.name.cmp(&right.name))
    });
    sorted
}

/// The display name of the role `name`: built-in roles are translated, custom roles
/// keep their name.
pub(crate) fn role_label(locale: Locale, name: &str) -> String {
    let built_in: [Role; BUILT_IN_LABELS.len()] = built_in_roles();
    built_in
        .into_iter()
        .zip(BUILT_IN_LABELS)
        .find(|(role, _label)| role.name == name)
        .map_or_else(|| name.to_owned(), |(_role, label)| tr(locale, label, None))
}

/// Whether `actor` may manage an account or API key holding the role `role`; an unknown
/// role counts as holding every permission on every router.
pub(crate) fn manages(state: &WebState, actor: &Role, role: &str) -> bool {
    let target = state
        .role(role)
        .unwrap_or_else(|| Role::new(String::new(), Permission::ALL, vec!["*".to_owned()]));
    actor.dominates(&target)
}

/// One choice of a role select.
pub(crate) struct RoleOption {
    /// Role name, the option value.
    name: String,
    /// Display label.
    label: String,
    /// Whether it is selected.
    selected: bool,
}

impl RoleOption {
    /// Role name, the option value.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Display label.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    /// Whether it is selected.
    pub(crate) const fn selected(&self) -> bool {
        self.selected
    }
}

/// The roles `user` may grant, in display order, `selected` chosen.
pub(crate) fn role_options(
    state: &WebState,
    user: &CurrentUser,
    selected: &str,
) -> Vec<RoleOption> {
    ordered(&state.roles())
        .into_iter()
        .filter(|role| user.role().dominates(role))
        .map(|role| RoleOption {
            label: role_label(user.locale(), &role.name),
            selected: role.name == selected,
            name: role.name,
        })
        .collect()
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_i18n::{bundle::tr, keys, locale::Locale};

    use super::role_label;

    /// Each built-in role gets its own label, and a custom role keeps its name.
    #[test]
    fn built_in_roles_are_labelled_by_name() {
        for (name, key) in [
            ("viewer", keys::WEB_ADMIN_ROLE_VIEWER),
            ("operator", keys::WEB_ADMIN_ROLE_OPERATOR),
            ("admin", keys::WEB_ADMIN_ROLE_ADMIN),
        ] {
            assert_eq!(
                role_label(Locale::En, name),
                tr(Locale::En, key, None),
                "{name}"
            );
        }
        assert_eq!(role_label(Locale::En, "lab-ops"), "lab-ops", "custom");
    }
}
