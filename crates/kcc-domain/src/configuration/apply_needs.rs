//! The steps of an apply that reboot or roll back the router, and so need `Destructive`.

/// What an apply will do beyond its own run of lines, as known before it contacts a router.
///
/// [`SafetyNet::apply_permissions`](super::SafetyNet::apply_permissions) turns it into the
/// permissions the apply needs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ApplyNeeds {
    /// Components are installed and committed, which reboots the router.
    pub install_components: bool,
    /// A saved configuration is restored onto the same hardware and the router restarted.
    pub raw_restore: bool,
    /// The run ends with a rollback chosen before it starts.
    pub finish_rollback: bool,
}

impl ApplyNeeds {
    /// With `install` saying whether components are installed first.
    #[inline]
    #[must_use]
    pub const fn installing_components(mut self, install: bool) -> Self {
        self.install_components = install;
        self
    }

    /// With `restore` saying whether a saved configuration is restored as it is.
    #[inline]
    #[must_use]
    pub const fn restoring_raw(mut self, restore: bool) -> Self {
        self.raw_restore = restore;
        self
    }

    /// With `rollback` saying whether the run ends with a rollback chosen up front.
    #[inline]
    #[must_use]
    pub const fn finishing_with_rollback(mut self, rollback: bool) -> Self {
        self.finish_rollback = rollback;
        self
    }

    /// Whether any step reboots or rolls back the router.
    #[must_use]
    pub(super) const fn destructive(self) -> bool {
        self.install_components || self.raw_restore || self.finish_rollback
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_app::permissions::Permission;

    use super::{super::SafetyNet, ApplyNeeds};

    #[test]
    fn only_rebooting_or_rolling_back_steps_add_destructive() {
        let run = [
            Permission::Read,
            Permission::Migrate,
            Permission::Write,
            Permission::Save,
        ];
        let mut destructive = run.to_vec();
        destructive.push(Permission::Destructive);
        let plain = ApplyNeeds::default();
        let rows = [
            (plain, run.to_vec()),
            (plain.installing_components(true), destructive.clone()),
            (plain.restoring_raw(true), destructive.clone()),
            (plain.finishing_with_rollback(true), destructive),
        ];
        for (needs, expected) in rows {
            assert_eq!(SafetyNet::apply_permissions(needs), expected, "{needs:?}");
        }
    }
}
