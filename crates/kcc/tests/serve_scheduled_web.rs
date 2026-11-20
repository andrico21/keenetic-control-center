//! `kcc serve` with the Web UI runs scheduled actions now through its scheduler.
//!
//! A policy schedule created on the scheduled actions page and run now changes the
//! router's running configuration only, is recorded with the clicking user and reported
//! to Telegram, and the router's dashboard and configuration page name it. The page asks
//! the scheduler before it stores a schedule: an unknown policy, a restart without the
//! router's name typed, and a role without `Destructive` are refused, and an operator may
//! not open the page. No test waits for a slot.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests drive the built process"
)]

#[path = "support/master_key.rs"]
mod master_key;
#[expect(dead_code, reason = "this suite reads the state through the stores")]
#[path = "serve_notify/process.rs"]
mod process;
#[path = "support/serve_port.rs"]
mod serve_port;
#[path = "support/spawning.rs"]
mod spawning;
#[path = "serve_scheduled_web/support.rs"]
mod support;
#[path = "serve_refresh/web.rs"]
mod web;

use fluent_bundle::FluentArgs;
use kcc_app::schedules::{ledger::RunState, model::Action};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use reqwest::StatusCode;

use crate::{
    support::{CLIENT, Fixture, ROUTER, TestResult},
    web::Browser,
};

/// The schedule the page creates.
const NAME: &str = "Kids offline";

/// The scheduled actions page.
const PAGE: &str = "/ui/admin/scheduled";

/// The form of a weekly policy switch of [`CLIENT`] to `policy`, named [`NAME`].
fn policy_form(policy: &str) -> Vec<(&'static str, String)> {
    vec![
        ("name", NAME.to_owned()),
        ("router", ROUTER.to_owned()),
        ("days", "mon".to_owned()),
        ("hour", "3".to_owned()),
        ("minute", "0".to_owned()),
        ("zone", "UTC".to_owned()),
        ("kind", "policy_switch".to_owned()),
        ("mac", CLIENT.to_owned()),
        ("policy", policy.to_owned()),
    ]
}

/// The form of a weekly restart named `name`, with `confirm` typed as the router's name.
fn reboot_form(name: &str, confirm: &str) -> Vec<(&'static str, String)> {
    vec![
        ("name", name.to_owned()),
        ("router", ROUTER.to_owned()),
        ("days", "sun".to_owned()),
        ("hour", "4".to_owned()),
        ("minute", "30".to_owned()),
        ("zone", "UTC".to_owned()),
        ("kind", "reboot".to_owned()),
        ("confirm_name", confirm.to_owned()),
    ]
}

/// `pairs` as the browser posts them.
fn borrowed<'pairs>(pairs: &'pairs [(&'static str, String)]) -> Vec<(&'static str, &'pairs str)> {
    pairs
        .iter()
        .map(|(field, value)| (*field, value.as_str()))
        .collect()
}

/// The message of a done policy switch of [`NAME`] to `Policy0`, as shipped in English.
fn done_message() -> String {
    let mut args = FluentArgs::new();
    args.set("name", NAME);
    args.set("router", ROUTER);
    args.set("policy", "Policy0");
    let done = tr(Locale::En, keys::NOTIFY_SCHEDULED_DONE_POLICY, Some(&args));
    let unsaved = tr(Locale::En, keys::NOTIFY_SCHEDULED_UNSAVED, None);
    format!("{done} {unsaved}")
}

/// Todo 15: a policy schedule created on the page and run now switches the policy.
///
/// It changes only the running configuration, is recorded `Succeeded { unsaved: true }`
/// with the clicking user, reaches Telegram, and is named by the dashboard and the
/// configuration page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_now_switches_the_policy_unsaved_and_reports_it() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let (http, base) = (fixture.http().clone(), fixture.base().to_owned());
    let alice = Browser::sign_in(&http, &base, "alice").await?;
    let dashboard = format!("/ui/r/{ROUTER}");
    let before = alice.get(&http, &base, &dashboard).await?.text().await?;

    let form = policy_form("Policy0");
    let created = alice.post(&http, &base, (PAGE, &borrowed(&form))).await?;
    assert_eq!(created.status(), StatusCode::OK, "the create form");
    let schedule = fixture.schedule(NAME)?;
    let after = alice.get(&http, &base, &dashboard).await?.text().await?;
    let run_now = format!("{PAGE}/run-now?id={}", schedule.id);
    let started = alice
        .post(&http, &base, (&run_now, &[("confirm", "yes")]))
        .await?;
    assert_eq!(started.status(), StatusCode::OK, "the run-now form");
    let message = fixture.message(NAME).await?;
    let runs = fixture.runs(&schedule.id)?;
    let config = alice
        .get(&http, &base, &format!("/ui/r/{ROUTER}/config"))
        .await?
        .text()
        .await?;
    drop(server.finish());

    assert!(!before.contains(NAME), "no schedule, no dashboard line");
    assert!(after.contains(NAME), "the dashboard names the schedule");
    let line = format!("ip hotspot host {CLIENT} policy Policy0");
    let running = fixture.router().running_config_text();
    assert!(running.contains(&line), "{running}");
    let startup = fixture.router().startup_config_text();
    assert!(!startup.contains(&line), "{startup}");
    let [run] = runs.as_slice() else {
        return Err(format!("one run expected: {runs:?}").into());
    };
    assert!(
        matches!(
            run.state,
            RunState::Succeeded {
                unsaved: true,
                checksum: Some(_)
            }
        ),
        "{run:?}"
    );
    assert_eq!(run.slot, None, "a run-now has no slot");
    assert_eq!(run.requested_by.as_deref(), Some("web:alice"));
    assert!(message.starts_with("[kcc]"), "{message}");
    assert!(message.contains("Policy0"), "{message}");
    assert_eq!(
        message,
        done_message(),
        "the done line, not the failure line"
    );
    assert!(config.contains(NAME), "the unsaved-schedule note: {config}");
    Ok(())
}

/// Todo 15: the scheduler's check refuses an unknown policy; a restart needs the name.
///
/// The refused edit changes nothing; a restart is stored only with the router's name
/// typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_scheduler_checks_edits_and_restarts_need_the_router_name() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let (http, base) = (fixture.http().clone(), fixture.base().to_owned());
    let alice = Browser::sign_in(&http, &base, "alice").await?;
    let form = policy_form("Policy0");
    drop(alice.post(&http, &base, (PAGE, &borrowed(&form))).await?);
    let id = fixture.schedule(NAME)?.id;
    let stored = fixture.schedules_json()?;

    let mut edit = policy_form("Policy9");
    edit.push(("id", id));
    let edited = alice
        .post(&http, &base, ("/ui/admin/scheduled/edit", &borrowed(&edit)))
        .await?;
    let unchanged = fixture.schedules_json()?;
    let untyped = reboot_form("Restart", "");
    drop(
        alice
            .post(&http, &base, (PAGE, &borrowed(&untyped)))
            .await?,
    );
    let without_name = fixture.schedules()?;
    let typed = reboot_form("Restart", ROUTER);
    drop(alice.post(&http, &base, (PAGE, &borrowed(&typed))).await?);
    let with_name = fixture.schedules()?;
    drop(server.finish());

    assert_eq!(
        edited.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "the dialog is shown again with the refusal"
    );
    assert_eq!(unchanged, stored, "a refused edit changes nothing");
    assert!(
        !without_name
            .iter()
            .any(|schedule| schedule.action == Action::Reboot),
        "a restart needs the router's name typed"
    );
    assert!(
        with_name
            .iter()
            .any(|schedule| schedule.action == Action::Reboot),
        "the typed name stores the restart"
    );
    Ok(())
}

/// Todo 15: roles without the permissions are refused.
///
/// An operator may not open the page, and a role that manages schedules but may not
/// restart a router cannot schedule a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn roles_without_the_permissions_are_refused() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let server = fixture.serve()?;
    let (http, base) = (fixture.http().clone(), fixture.base().to_owned());
    let bob = Browser::sign_in(&http, &base, "bob").await?;
    let carol = Browser::sign_in(&http, &base, "carol").await?;

    let operator = bob.get(&http, &base, PAGE).await?;
    let keeper = carol.get(&http, &base, PAGE).await?;
    let restart = reboot_form("Restart", ROUTER);
    let refused = carol
        .post(&http, &base, (PAGE, &borrowed(&restart)))
        .await?;
    let stored = fixture.schedules()?;
    drop(server.finish());

    assert_eq!(operator.status(), StatusCode::FORBIDDEN, "an operator");
    assert_eq!(keeper.status(), StatusCode::OK, "ManageSchedules opens it");
    assert_eq!(
        refused.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "the dialog is shown again with the refusal"
    );
    assert!(
        stored.is_empty(),
        "no restart without Destructive: {stored:?}"
    );
    Ok(())
}
