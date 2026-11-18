//! Ordinary firewall writes retain their original permission boundary.

use kcc_app::{
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, migration, model::Profile};

use super::support::{Env, TestResult, router};

/// A writer can edit an unbound list and bind it to a non-management interface.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ordinary_firewall_writer_needs_no_recovery_permission() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let (address, handle) = FakeRouter::builder(Profile::default())
            .reached_directly()
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        let mut roles = RolesDocument::default();
        roles.roles.push(Role::new(
            "writer".to_owned(),
            [Permission::Read, Permission::Write],
            vec!["*".to_owned()],
        ));
        StateStore::open(&env.state_dir())?.write(&roles)?;
        for role in ["writer", "operator"] {
            env.write_config(&format!(
                "[cli]\nrole = \"{role}\"\n{}",
                router("lab-1", address, &password)
            ))?;
            let acl = format!("Ordinary-{role}");
            for args in [
                vec![
                    "firewall",
                    "rule",
                    &acl,
                    "--protocol",
                    "ip",
                    "--source",
                    "192.0.2.10",
                    "--destination",
                    "198.51.100.10",
                ],
                vec!["firewall", "bind", &acl, "--interface", "ISP"],
            ] {
                let before = handle.request_log().len();
                let run = env.kcc(&args)?;
                assert_eq!(run.code, 0_i32, "{mode} {role}: {run:?}");
                let commands = handle
                    .request_log()
                    .iter()
                    .skip(before)
                    .filter_map(|record| record.command().map(str::to_owned))
                    .collect::<Vec<_>>();
                assert_eq!(
                    commands.len(),
                    1,
                    "ordinary write without timer: {commands:?}"
                );
                assert!(
                    !commands.iter().any(|line| line.contains("system")),
                    "no recovery commands"
                );
            }
        }
        handle.shutdown().await?;
    }
    Ok(())
}
