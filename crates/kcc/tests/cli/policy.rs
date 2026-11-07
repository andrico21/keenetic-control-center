//! The CLI principal: `[cli] role` and `router_scope`, refusals before any request, and
//! audit entries with `actor=cli:<user>`.

use core::error::Error;

use kcc_app::audit::{ActorKind, read_entries};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle};

use super::support::{Env, TestResult, USER, router};

/// A registration write against one client of the fake.
const REGISTER: [&str; 6] = [
    "clients",
    "register",
    "--mac",
    "02:00:00:00:10:02",
    "--name",
    "desk",
];

/// Fakes `prod-1` and `lab-1` and a configuration with `[cli] role`/`router_scope`.
async fn fleet(role: &str) -> Result<(Env, Handle, Handle), Box<dyn Error>> {
    let (prod_address, prod) = FakeRouter::spawn().await?;
    let (lab_address, lab) = FakeRouter::spawn().await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&format!(
        "[cli]\nrole = {role:?}\nrouter_scope = [\"lab-*\"]\n\n{}{}",
        router("prod-1", prod_address, &password),
        router("lab-1", lab_address, &password)
    ))?;
    Ok((env, prod, lab))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn viewer_write_outside_scope_exits_10_and_sends_nothing() -> TestResult {
    let (env, prod, lab) = fleet("viewer").await?;
    let mut args = vec!["--router", "prod-1"];
    args.extend(REGISTER);
    let run = env.kcc(&args)?;
    assert_eq!(run.code, 10_i32, "{run:?}");
    assert!(
        run.stderr
            .contains(&tr(Locale::En, keys::CLI_ERROR_POLICY, None)),
        "{}",
        run.stderr
    );
    assert_eq!(prod.request_count(), 0, "{:?}", prod.request_log());
    let mut in_scope = vec!["--router", "lab-1"];
    in_scope.extend(REGISTER);
    let refused = env.kcc(&in_scope)?;
    assert_eq!(
        refused.code, 10_i32,
        "a viewer may not write in scope either: {refused:?}"
    );
    assert_eq!(lab.request_count(), 0, "{:?}", lab.request_log());
    let entries = read_entries(&env.state_dir())?;
    assert!(
        entries
            .iter()
            .all(|entry| entry.action == "cli.refused" && entry.outcome == "forbidden"),
        "{entries:?}"
    );
    prod.shutdown().await?;
    lab.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_write_in_scope_is_audited_as_the_cli_user() -> TestResult {
    let (env, prod, lab) = fleet("operator").await?;
    let mut out_of_scope = vec!["--router", "prod-1"];
    out_of_scope.extend(REGISTER);
    let refused = env.kcc(&out_of_scope)?;
    assert_eq!(
        refused.code, 10_i32,
        "router_scope excludes prod-1: {refused:?}"
    );
    assert_eq!(prod.request_count(), 0, "{:?}", prod.request_log());
    let mut args = vec!["--router", "lab-1"];
    args.extend(REGISTER);
    let run = env.kcc(&args)?;
    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        lab.running_config_text().contains("desk"),
        "the change reached the router"
    );
    let entries = read_entries(&env.state_dir())?;
    let change = entries
        .iter()
        .find(|entry| entry.action == "router.change_cli")
        .ok_or("no audit entry for the change")?;
    assert_eq!(change.actor.kind, ActorKind::Cli);
    assert_eq!(change.actor.id, format!("cli:{USER}"));
    assert_eq!(change.router.as_deref(), Some("lab-1"));
    assert_eq!(prod.request_count(), 0, "{:?}", prod.request_log());
    prod.shutdown().await?;
    lab.shutdown().await?;
    Ok(())
}
