//! Whose authority a run has: the schedule's owner as it is at run time.
//!
//! A Web owner is an account in `users.json` with its role from the roles in force; the
//! CLI owner is the `[cli] role` with the `[cli] router_scope` of the `kcc.toml` the server
//! loaded. A missing, disabled or out-of-scope owner makes the schedule `owner_unavailable`;
//! a role that lacks `ManageSchedules` or a permission of the action (on the router, and
//! for a preset on the preset's source router) makes it `forbidden`.

use core::fmt::Debug;

use kcc_app::{
    accounts::{AccountError, AccountStore},
    permissions::{Permission, Role},
    registry::{authorize, scope_matches},
    role_source::RoleSource,
    schedules::model::{Owner, PRESET_SOURCE_PERMISSIONS, PauseReason, Schedule},
    settings::CliConfig,
};

/// A Web account as a run sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Lookup {
    /// No such account.
    Missing,
    /// The account is disabled.
    Disabled,
    /// The account holds the role of this name.
    Role(String),
}

/// Finds Web accounts.
pub(crate) trait AccountLookup: Debug + Send + Sync {
    /// The account `username`.
    ///
    /// # Errors
    ///
    /// The account store's error.
    fn find(&self, username: &str) -> Result<Lookup, AccountError>;
}

impl AccountLookup for AccountStore {
    fn find(&self, username: &str) -> Result<Lookup, AccountError> {
        Ok(self
            .list()?
            .into_iter()
            .find(|account| account.username == username)
            .map_or(Lookup::Missing, |account| {
                if account.disabled {
                    Lookup::Disabled
                } else {
                    Lookup::Role(account.role)
                }
            }))
    }
}

/// Who a run's owner is, with what a lookup found.
#[derive(Clone, Copy, Debug)]
pub(super) struct Found<'found> {
    /// The roles in force.
    roles: &'found RoleSource,
    /// `[cli]` as loaded at start.
    cli: &'found CliConfig,
}

impl<'found> Found<'found> {
    /// Owners resolved against `roles` and `cli`.
    pub(super) const fn new(roles: &'found RoleSource, cli: &'found CliConfig) -> Self {
        Self { roles, cli }
    }

    /// The role `schedule`'s owner acts with on its router, given `web` for a Web owner.
    ///
    /// # Errors
    ///
    /// [`PauseReason::OwnerUnavailable`] for a missing or disabled owner, an unknown role,
    /// or a router outside the owner's scope.
    pub(super) fn role(self, schedule: &Schedule, web: Lookup) -> Result<Role, PauseReason> {
        let role = match &schedule.owner {
            Owner::Web { username: _ } => match web {
                Lookup::Role(name) => self.roles.find(&name),
                Lookup::Missing | Lookup::Disabled => None,
            },
            Owner::Cli { os_user: _ } => scope_matches(&self.cli.router_scope, &schedule.router)
                .then(|| self.roles.find(&self.cli.role))
                .flatten(),
            _ => None,
        }
        .ok_or(PauseReason::OwnerUnavailable)?;
        scope_matches(&role.router_scope, &schedule.router)
            .then_some(role)
            .ok_or(PauseReason::OwnerUnavailable)
    }
}

/// Requires `ManageSchedules` and every permission of `schedule`'s action on its router.
///
/// # Errors
///
/// [`PauseReason::Forbidden`].
pub(super) fn permitted(role: &Role, schedule: &Schedule) -> Result<(), PauseReason> {
    if !role.grants(Permission::ManageSchedules) {
        return Err(PauseReason::Forbidden);
    }
    schedule
        .action
        .permissions()
        .iter()
        .try_for_each(|permission| authorize(role, *permission, &schedule.router))
        .map_err(|_denied| PauseReason::Forbidden)
}

/// Requires `Read` and `Migrate` on a preset's `source` router, when it names one.
///
/// # Errors
///
/// [`PauseReason::Forbidden`].
pub(super) fn source_permitted(role: &Role, source: Option<&str>) -> Result<(), PauseReason> {
    source.map_or(Ok(()), |router| {
        PRESET_SOURCE_PERMISSIONS
            .iter()
            .try_for_each(|permission| authorize(role, *permission, router))
            .map_err(|_denied| PauseReason::Forbidden)
    })
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::error::Error;

    use kcc_app::{
        permissions::{Permission, Role},
        role_source::RoleSource,
        schedules::model::{Owner, PauseReason},
        settings::CliConfig,
    };

    use super::{Found, Lookup, permitted};
    use crate::server_schedules::tests::rig::schedule_of;

    /// Roles `ops` (everything on `home*`) and `viewer` (read only).
    fn roles() -> RoleSource {
        RoleSource::new(vec![
            Role::new("ops".to_owned(), Permission::ALL, vec!["home*".to_owned()]),
            Role::new(
                "viewer".to_owned(),
                [Permission::Read],
                vec!["*".to_owned()],
            ),
        ])
    }

    /// Todo 13: a disabled, missing or unknown-role Web owner is unavailable; an enabled
    /// one acts with its role.
    #[test]
    fn a_web_owner_needs_an_enabled_account_with_a_known_role() -> Result<(), Box<dyn Error>> {
        let roles = roles();
        let cli = CliConfig::default();
        let found = Found::new(&roles, &cli);
        let schedule = schedule_of(
            "home",
            Owner::Web {
                username: "alice".to_owned(),
            },
        )?;

        for lookup in [
            Lookup::Disabled,
            Lookup::Missing,
            Lookup::Role("gone".to_owned()),
        ] {
            assert_eq!(
                found.role(&schedule, lookup).err(),
                Some(PauseReason::OwnerUnavailable)
            );
        }
        let role = found
            .role(&schedule, Lookup::Role("ops".to_owned()))
            .map_err(|reason| format!("{reason:?}"))?;
        assert_eq!(role.name, "ops");
        Ok(())
    }

    /// Todo 13: a CLI owner outside `[cli] router_scope` or the role's scope is
    /// unavailable.
    #[test]
    fn a_cli_owner_needs_both_scopes() -> Result<(), Box<dyn Error>> {
        let roles = roles();
        let mut cli = CliConfig::default();
        cli.role = "ops".to_owned();
        cli.router_scope = vec!["office".to_owned()];
        let owner = Owner::Cli {
            os_user: "root".to_owned(),
        };
        let home = schedule_of("home", owner.clone())?;
        let office = schedule_of("office", owner)?;

        assert_eq!(
            Found::new(&roles, &cli).role(&home, Lookup::Missing).err(),
            Some(PauseReason::OwnerUnavailable),
            "outside [cli] router_scope"
        );
        assert_eq!(
            Found::new(&roles, &cli)
                .role(&office, Lookup::Missing)
                .err(),
            Some(PauseReason::OwnerUnavailable),
            "outside the role's scope"
        );
        Ok(())
    }

    /// Todo 13: a role without `Destructive` may not run a reboot.
    #[test]
    fn a_reboot_needs_destructive() -> Result<(), Box<dyn Error>> {
        let schedule = schedule_of(
            "home",
            Owner::Web {
                username: "alice".to_owned(),
            },
        )?;
        let lacking = Role::new(
            "ops".to_owned(),
            Permission::ALL
                .into_iter()
                .filter(|permission| *permission != Permission::Destructive),
            vec!["*".to_owned()],
        );
        assert_eq!(permitted(&lacking, &schedule), Err(PauseReason::Forbidden));
        Ok(())
    }
}
