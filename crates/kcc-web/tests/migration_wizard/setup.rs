//! The migration wizard's fixture: its accounts and roles, and the fake routers it serves.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support is not rendered API documentation; every error fails the test"
)]

use kcc_app::permissions::{Permission, Role, built_in_roles};
use kcc_testkit::{
    FakeRouter, FakeRouterBuilder, FaultInjection, migration,
    model::{Firmware, Model, Profile},
};

use crate::support::{
    base::Account,
    build::{Setup, Wiring},
    outcome::TestResult,
    web::Fixture,
};

/// One account per built-in role and the apply-permission test roles.
const ACCOUNTS: [Account<'static>; 7] = [
    ("viewer", "viewer", Some("en")),
    ("operator", "operator", Some("en")),
    ("admin", "admin", Some("en")),
    ("migrator", "migrator", Some("en")),
    ("scoped", "giga-migrator", Some("en")),
    ("without-save", "without-save", Some("ru")),
    ("without-write-save", "without-write-save", Some("kk")),
];

/// The fixture with a fault-free target.
pub(crate) async fn fixture() -> TestResult<Fixture> {
    with_target_faults(FaultInjection::default()).await
}

/// The fixture whose target `ultra` has `faults`.
pub(crate) async fn with_target_faults(faults: FaultInjection) -> TestResult<Fixture> {
    with_mode("router", faults).await
}

/// The fixture whose target `ultra` reports `mode` and has `faults`.
// NOT cancel-safe: fixture services may start before cancellation.
pub(crate) async fn with_mode(mode: &str, faults: FaultInjection) -> TestResult<Fixture> {
    with_target(mode, FakeRouter::builder(Profile::default()).faults(faults)).await
}

/// The fixture whose target `ultra` runs in `mode` as `target` builds it.
// NOT cancel-safe: fixture services may start before cancellation.
pub(crate) async fn with_target(mode: &str, target: FakeRouterBuilder) -> TestResult<Fixture> {
    Setup {
        accounts: ACCOUNTS.to_vec(),
        roles: roles(),
        routers: routers(mode, target)?,
        wiring: Wiring::Wizards,
        ..Setup::default()
    }
    .build()
    .await
}

/// The built-in roles and `giga-migrator`.
fn roles() -> Vec<Role> {
    let mut roles = Vec::from(built_in_roles());
    roles.push(Role::new(
        "migrator".to_owned(),
        [
            Permission::Read,
            Permission::Write,
            Permission::Save,
            Permission::Migrate,
            Permission::Destructive,
        ],
        vec!["*".to_owned()],
    ));
    roles.push(Role::new(
        "giga-migrator".to_owned(),
        [Permission::Read, Permission::Migrate],
        vec!["giga".to_owned()],
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

/// `giga`, `ultra` (built by `target`, in `mode`) and `legacy`.
///
/// Both targets report `Bridge0` holding the address kcc connects to, as a real router
/// managed over its home network does.
fn routers(mode: &str, target: FakeRouterBuilder) -> TestResult<Vec<(&'static str, FakeRouter)>> {
    let mut managed = migration::Fixture::default();
    managed.interfaces = Some(serde_json::json!({
        "Bridge0": {"type": "Bridge", "link": "up", "address": "127.0.0.1"}
    }));
    let mut fixture = managed.clone();
    fixture.mode = Some(mode.to_owned());
    Ok(vec![
        (
            "giga",
            FakeRouter::builder(Profile::latest(Model::Kn1010)).build()?,
        ),
        ("ultra", target.build()?.with_migration(fixture)),
        (
            "legacy",
            FakeRouter::builder(Profile::new(Model::Kn1811, Firmware::V4_3)?)
                .build()?
                .with_migration(managed),
        ),
    ])
}
