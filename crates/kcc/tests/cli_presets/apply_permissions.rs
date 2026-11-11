//! Preset and copy apply authorization before source or target discovery.

use kcc_app::{
    audit::read_entries,
    permissions::{Permission, Role, RolesDocument},
    persist::StateStore,
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::model::Profile;

use super::{fixture::Pair, support::TestResult};

fn capture(pair: &Pair) -> TestResult {
    let run = pair.env.kcc(&[
        "preset",
        "capture",
        "--from",
        "fake-a",
        "--groups",
        "dns-secure",
        "--name",
        "apply-permission",
    ])?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preset_and_copy_apply_require_complete_permissions_before_any_router_request() -> TestResult
{
    for role in ["operator", "migrator"] {
        let pair = Pair::start(Profile::default()).await?;
        capture(&pair)?;
        let mut roles = RolesDocument::default();
        roles.roles.push(Role::new(
            "migrator".to_owned(),
            [
                Permission::Read,
                Permission::Write,
                Permission::Migrate,
                Permission::Destructive,
            ],
            vec!["*".to_owned()],
        ));
        StateStore::open(&pair.env.state_dir())?.write(&roles)?;
        pair.with_cli(&format!("role = {role:?}"))?;
        for args in [
            vec![
                "--router",
                "fake-b",
                "--json",
                "preset",
                "apply",
                "apply-permission",
                "--yes",
                "--finish",
                "save",
            ],
            vec![
                "--json",
                "copy",
                "--from",
                "fake-a",
                "--to",
                "fake-b",
                "--groups",
                "dns-secure",
                "--yes",
                "--finish",
                "save",
            ],
        ] {
            let before = pair.requests();

            let refused = pair.env.kcc(&args)?;

            assert_eq!(refused.code, 10_i32, "{role} {args:?}: {refused:?}");
            assert_eq!(pair.requests(), before, "{role} {args:?}: router traffic");
            assert!(
                refused
                    .stderr
                    .contains(&tr(Locale::En, keys::CLI_APPLY_RECOVERY_FORBIDDEN, None)),
                "{role} {args:?}: {refused:?}"
            );
        }
        let refusals = read_entries(&pair.env.state_dir())?
            .into_iter()
            .filter(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden")
            .count();
        assert_eq!(refusals, 2, "{role}: each refusal is audited");
        pair.stop().await?;
    }
    Ok(())
}
