//! Preset and copy apply authorization before source or target discovery.

use fluent_bundle::FluentArgs;
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
        let (finish, missing, held) = if role == "operator" {
            (
                "rollback",
                keys::WEB_ADMIN_PERMISSION_DESTRUCTIVE,
                keys::WEB_ADMIN_PERMISSION_SAVE,
            )
        } else {
            (
                "save",
                keys::WEB_ADMIN_PERMISSION_SAVE,
                keys::WEB_ADMIN_PERMISSION_WRITE,
            )
        };
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
                finish,
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
                finish,
            ],
        ] {
            let before = pair.requests();

            let refused = pair.env.kcc(&args)?;

            assert_eq!(refused.code, 10_i32, "{role} {args:?}: {refused:?}");
            assert_eq!(pair.requests(), before, "{role} {args:?}: router traffic");
            let mut message_args = FluentArgs::new();
            message_args.set("missing", tr(Locale::En, missing, None));
            assert!(
                refused.stderr.contains(&tr(
                    Locale::En,
                    keys::CLI_APPLY_RECOVERY_FORBIDDEN,
                    Some(&message_args)
                )),
                "{role} {args:?}: {refused:?}"
            );
            assert!(
                refused.stderr.contains(&tr(Locale::En, missing, None)),
                "{role} names the missing permission: {refused:?}"
            );
            assert!(
                !refused.stderr.contains(&tr(Locale::En, held, None)),
                "{role} holds that permission: {refused:?}"
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
