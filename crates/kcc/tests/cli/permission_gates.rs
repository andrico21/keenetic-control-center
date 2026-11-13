//! CLI permission gates reject dangerous operations before a router mutation.

use core::{error::Error, net::SocketAddr};

use kcc_app::{
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, migration, model::Profile};

use super::support::{Env, TestResult, router};

#[path = "permission_gates/apply.rs"]
mod apply;
#[path = "permission_gates/curated.rs"]
mod curated;
#[path = "permission_gates/raw.rs"]
mod raw;
#[path = "permission_gates/raw_management.rs"]
mod raw_management;
#[path = "permission_gates/recovery.rs"]
mod recovery;

/// Builds a fake router in `mode` and configures it as `lab-1` for `role`.
async fn lab(mode: &str, role: &str) -> Result<(Env, Handle, SocketAddr), Box<dyn Error>> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some(mode.to_owned());
    let fake = FakeRouter::builder(Profile::default())
        .build()?
        .with_migration(scenario);
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    drop(env.write("router.password", DEFAULT_PASSWORD)?);
    env.write_config(&env_config(&env, role, address))?;
    Ok((env, handle, address))
}

/// Adds a custom role to the state document used by the CLI process.
fn add_role(env: &Env, name: &str, permissions: &[Permission]) -> TestResult {
    let mut roles = RolesDocument::default();
    roles.roles.push(Role::new(
        name.to_owned(),
        permissions.iter().copied(),
        vec!["*".to_owned()],
    ));
    StateStore::open(&env.state_dir())?.write(&roles)?;
    Ok(())
}

/// Counts mutation requests after `before`; discovery reads are deliberately excluded.
fn mutation_count(handle: &Handle, before: usize) -> usize {
    handle
        .request_log()
        .into_iter()
        .skip(before)
        .filter(|request| {
            matches!(request.method().as_str(), "POST" | "DELETE")
                && request.path().starts_with("/rci")
        })
        .count()
}

/// Returns a complete config for an already-running fake handle.
fn env_config(env: &Env, role: &str, address: SocketAddr) -> String {
    let password = env.path("router.password");
    format!(
        "[cli]\nrole = {role:?}\n{}",
        router("lab-1", address, &password)
    )
}

/// Parser commands the fake received after the first `before` requests.
fn commands_after(handle: &Handle, before: usize) -> Vec<String> {
    handle
        .request_log()
        .iter()
        .skip(before)
        .filter_map(|record| record.command().map(str::to_owned))
        .collect()
}

/// The arm and disarm command lines of the recovery timer in `mode`.
fn edges(mode: &str) -> (&'static str, &'static str) {
    if mode == "router" {
        (
            "system configuration fail-safe timer reboot 300",
            "no system configuration fail-safe timer",
        )
    } else {
        ("system reboot 300", "no system reboot")
    }
}
