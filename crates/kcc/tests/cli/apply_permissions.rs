//! Migration apply authorization before target discovery.

use fluent_bundle::FluentArgs;
use kcc_app::{
    audit::read_entries,
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, migration, model::Profile};

use super::support::{Env, TestResult, router};

const SOURCE: &str = "! $$$ Model: Keenetic Giga\n! $$$ Version: 5.1.0\ninterface Bridge11\n description migrated-permission\n!\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migration_apply_requires_complete_permissions_before_any_router_request() -> TestResult {
    for mode in ["router", "extender"] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some(mode.to_owned());
        let (address, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario)
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let env = Env::new("")?;
        let password = env.write("router.password", DEFAULT_PASSWORD)?;
        let routers = router("target", address, &password);
        env.write_config(&routers)?;
        let source_file = env.write("source.txt", SOURCE)?;
        let source = format!("file:{}", source_file.display());
        let plan_file = env.path("plan.json");
        let plan = plan_file.to_str().ok_or("non-UTF-8 plan path")?;
        let planned = env.kcc(&["migrate", "plan", "--from", &source, "--out", plan])?;
        assert_eq!(planned.code, 0_i32, "{mode}: {planned:?}");
        let mut roles = RolesDocument::default();
        roles.roles.push(Role::new(
            "migrator".to_owned(),
            [
                Permission::Read,
                Permission::Write,
                Permission::Migrate,
                Permission::Destructive,
            ],
            vec!["target".to_owned()],
        ));
        StateStore::open(&env.state_dir())?.write(&roles)?;

        for (role, missing, held) in [
            (
                "operator",
                keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE,
                keys::WEB_ADMIN_PERMISSION_SAVE,
            ),
            (
                "migrator",
                keys::WEB_ADMIN_PERMISSION_SAVE,
                keys::WEB_ADMIN_PERMISSION_WRITE,
            ),
        ] {
            env.write_config(&format!("[cli]\nrole = {role:?}\n{routers}"))?;
            let before = handle.request_count();

            let refused = env.kcc(&[
                "--json", "migrate", "apply", "--from", &source, "--plan", plan,
            ])?;

            assert_eq!(refused.code, 10_i32, "{mode} {role}: {refused:?}");
            assert_eq!(
                handle.request_count(),
                before,
                "{mode} {role}: router traffic"
            );
            let mut args = FluentArgs::new();
            args.set("missing", tr(Locale::En, missing, None));
            assert!(
                refused.stderr.contains(&tr(
                    Locale::En,
                    keys::CLI_APPLY_RECOVERY_FORBIDDEN,
                    Some(&args)
                )),
                "{mode} {role}: {refused:?}"
            );
            assert!(
                refused.stderr.contains(&tr(Locale::En, missing, None)),
                "{mode} {role} names the missing permission: {refused:?}"
            );
            assert!(
                !refused.stderr.contains(&tr(Locale::En, held, None)),
                "{mode} {role} holds that permission: {refused:?}"
            );
        }
        let refusals = read_entries(&env.state_dir())?
            .into_iter()
            .filter(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden")
            .count();
        assert_eq!(refusals, 2, "{mode}: each refusal is audited");
        handle.shutdown().await?;
    }
    Ok(())
}
