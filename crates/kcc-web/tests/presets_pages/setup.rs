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

/// One account per built-in role, `migrator` (every permission but `RevealSecrets`) and
/// `scoped` (`migrator`'s permissions on `lab-*` routers only).
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
    for (name, role, locale) in [
        ("viewer", "viewer", "en"),
        ("operator", "operator", "en"),
        ("admin", "admin", "en"),
        ("migrator", "migrator", "en"),
        ("scoped", "lab-migrator", "en"),
        ("without-save", "without-save", "ru"),
        ("without-write-save", "without-write-save", "kk"),
    ] {
        accounts.create(
            NewAccount::new(
                name.to_owned(),
                SecretString::from(password.to_owned()),
                role.to_owned(),
            )
            .with_locale(locale.to_owned()),
        )?;
    }
    Ok(accounts)
}

/// The built-in roles, `migrator` and `lab-migrator`.
pub(crate) fn roles() -> Vec<Role> {
    let applying = [
        Permission::Read,
        Permission::Write,
        Permission::Save,
        Permission::Destructive,
        Permission::Migrate,
    ];
    let mut roles = Vec::from(built_in_roles());
    roles.push(Role::new(
        "migrator".to_owned(),
        applying,
        vec!["*".to_owned()],
    ));
    roles.push(Role::new(
        "lab-migrator".to_owned(),
        applying,
        vec!["lab-*".to_owned()],
    ));
    roles.push(Role::new(
        "without-save".to_owned(),
        [
            Permission::Read,
            Permission::Write,
            Permission::Migrate,
            Permission::Destructive,
        ],
        vec!["*".to_owned()],
    ));
    roles.push(Role::new(
        "without-write-save".to_owned(),
        [
            Permission::Read,
            Permission::Migrate,
            Permission::Destructive,
        ],
        vec!["*".to_owned()],
    ));
    roles
}

/// Serves `prod-1`, `lab-1` (in router mode) and `lab-2`, and registers them in
/// `registry` with password files in `directory`.
pub(crate) async fn routers(
    directory: &Path,
    registry: &RouterRegistry,
    (mode, faults): (&str, FaultInjection),
) -> TestResult<Vec<(&'static str, Handle)>> {
    let router_mode = || {
        let mut fixture = migration::Fixture::default();
        fixture.mode = Some(mode.to_owned());
        fixture
    };
    let routers = [
        (
            "prod-1",
            FakeRouter::builder(Profile::default())
                .build()?
                .with_migration(router_mode()),
        ),
        (
            "lab-1",
            FakeRouter::builder(Profile::latest(Model::Kn3810))
                .faults(faults)
                .build()?
                .with_migration(router_mode()),
        ),
        (
            "lab-2",
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
