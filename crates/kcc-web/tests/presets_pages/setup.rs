//! The presets pages' fixture: its accounts and roles, and the fake routers it serves.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

use kcc_app::permissions::{Permission, Role, built_in_roles};
use kcc_testkit::{
    FakeRouter, FaultInjection, migration,
    model::{Firmware, Model, Profile},
};

use crate::support::{
    base::Account,
    build::{Setup, Wiring},
    outcome::TestResult,
    web::Fixture,
};

/// One account per built-in role, `migrator` (every permission but `RevealSecrets`) and
/// `scoped` (`migrator`'s permissions on `lab-*` routers only).
const ACCOUNTS: [Account<'static>; 7] = [
    ("viewer", "viewer", Some("en")),
    ("operator", "operator", Some("en")),
    ("admin", "admin", Some("en")),
    ("migrator", "migrator", Some("en")),
    ("scoped", "lab-migrator", Some("en")),
    ("without-save", "without-save", Some("ru")),
    ("without-write-save", "without-write-save", Some("kk")),
];

/// The fixture.
pub(crate) async fn fixture() -> TestResult<Fixture> {
    with_faults(FaultInjection::default()).await
}

/// The fixture with target-router faults for recovery outcomes.
// NOT cancel-safe: fixture services may start before cancellation.
pub(crate) async fn with_faults(faults: FaultInjection) -> TestResult<Fixture> {
    with_mode("router", faults).await
}

/// The fixture whose target `lab-1` reports `mode` and has `faults`.
// NOT cancel-safe: fixture services may start before cancellation.
pub(crate) async fn with_mode(mode: &str, faults: FaultInjection) -> TestResult<Fixture> {
    Setup {
        accounts: ACCOUNTS.to_vec(),
        roles: roles(),
        routers: routers(mode, faults)?,
        wiring: Wiring::Wizards,
        ..Setup::default()
    }
    .build()
    .await
}

/// The built-in roles, `migrator` and `lab-migrator`.
fn roles() -> Vec<Role> {
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

/// `prod-1`, `lab-1` (in `mode`, with `faults`) and `lab-2`.
fn routers(mode: &str, faults: FaultInjection) -> TestResult<Vec<(&'static str, FakeRouter)>> {
    let router_mode = || {
        let mut fixture = migration::Fixture::default();
        fixture.mode = Some(mode.to_owned());
        fixture
    };
    Ok(vec![
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
    ])
}
