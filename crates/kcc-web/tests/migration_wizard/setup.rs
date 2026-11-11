//! Building the fixture's parts: its accounts and roles, and the fake routers registered
//! as profiles.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

use alloc::sync::Arc;
use core::{net::SocketAddr, time::Duration};
use std::{fs, path::Path};

use kcc_app::{
    accounts::{AccountStore, Clock, NewAccount},
    permissions::{Permission, Role, built_in_roles},
    persist::StateStore,
    registry::{ManagedRouterProfile, RouterRegistry},
    secrets::MasterKey,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, migration,
    model::{Firmware, Model, Profile},
};
use secrecy::SecretString;
use url::Url;

use crate::support::TestResult;

/// One account per built-in role and `scoped`, who may migrate `giga` only.
pub(crate) fn accounts(
    state: &StateStore,
    clock: &Arc<dyn Clock>,
    password: &str,
) -> TestResult<Arc<AccountStore>> {
    let accounts = Arc::new(AccountStore::new(
        state.clone(),
        MasterKey::generate()?,
        Duration::from_secs(60),
        Arc::clone(clock),
    ));
    for (name, role) in [
        ("viewer", "viewer"),
        ("operator", "operator"),
        ("admin", "admin"),
        ("migrator", "migrator"),
        ("scoped", "giga-migrator"),
    ] {
        accounts.create(NewAccount::new(
            name.to_owned(),
            SecretString::from(password.to_owned()),
            role.to_owned(),
        ))?;
    }
    Ok(accounts)
}

/// The built-in roles and `giga-migrator`.
pub(crate) fn roles() -> Vec<Role> {
    let mut roles = Vec::from(built_in_roles());
    roles.push(Role::new(
        "migrator".to_owned(),
        [
            Permission::Read,
            Permission::Write,
            Permission::Save,
            Permission::Migrate,
        ],
        vec!["*".to_owned()],
    ));
    roles.push(Role::new(
        "giga-migrator".to_owned(),
        [Permission::Read, Permission::Migrate],
        vec!["giga".to_owned()],
    ));
    roles
}

/// Serves `giga`, `ultra` (with `faults`, in router mode) and `legacy`, and registers
/// them in `registry` with password files in `directory`.
pub(crate) async fn routers(
    directory: &Path,
    registry: &RouterRegistry,
    (mode, faults): (&str, FaultInjection),
) -> TestResult<Vec<(&'static str, Handle)>> {
    let mut target = migration::Fixture::default();
    target.mode = Some(mode.to_owned());
    let routers = [
        (
            "giga",
            FakeRouter::builder(Profile::latest(Model::Kn1010)).build()?,
        ),
        (
            "ultra",
            FakeRouter::builder(Profile::default())
                .faults(faults)
                .build()?
                .with_migration(target),
        ),
        (
            "legacy",
            FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V4_3)?).build()?,
        ),
    ];
    let admin = built_in_roles()
        .into_iter()
        .find(|role| role.name == "admin")
        .ok_or("no admin role")?;
    let mut handles = Vec::new();
    for (id, fake) in routers {
        let (address, handle) = fake.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let password_file = directory.join(format!("{id}-password"));
        fs::write(&password_file, DEFAULT_PASSWORD)?;
        registry
            .create(
                &admin,
                ManagedRouterProfile::new(
                    id.to_owned(),
                    Url::parse(&format!("http://{address}"))?,
                    DEFAULT_LOGIN.to_owned(),
                    password_file,
                ),
            )
            .await?;
        handles.push((id, handle));
    }
    Ok(handles)
}
