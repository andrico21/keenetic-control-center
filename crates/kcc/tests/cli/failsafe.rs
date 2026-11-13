//! The fail-safe timer's steps and the commands the router carries out by restarting say
//! what the router did: never the headline of an ordinary change or its advice to save.

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, time::Duration};

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, Handle, migration,
    model::Profile,
    time::{Clock, MockClock},
};

use super::support::{Env, Run, TestResult, router};

/// A fake router in `mode`, with a controllable clock, as `lab-1`.
async fn lab(mode: &str) -> Result<(Env, Handle, Arc<MockClock>), Box<dyn Error>> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some(mode.to_owned());
    let clock = Arc::new(MockClock::new());
    let concrete_clock = Arc::clone(&clock);
    let router_clock: Arc<dyn Clock> = concrete_clock;
    let fake = FakeRouter::builder(Profile::default())
        .clock(router_clock)
        .build()?
        .with_migration(scenario);
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    Ok((env, handle, clock))
}

/// Asserts that `run` succeeded and printed `headline` in `locale`, and no headline of an
/// ordinary change.
fn says(run: &Run, locale: Locale, headline: MessageKey) {
    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        run.stdout.contains(&tr(locale, headline, None)),
        "{headline:?}: {run:?}"
    );
    for ordinary in [keys::CLI_APPLIED, keys::CLI_APPLIED_PERSISTED] {
        let text = tr(locale, ordinary, None);
        assert!(
            !run.stdout.contains(&text) && !run.stderr.contains(&text),
            "{ordinary:?}: {run:?}"
        );
    }
}

/// Arm, keep-alive, commit and rollback say what the router did, in English and Russian.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failsafe_steps_say_what_the_router_did() -> TestResult {
    let (env, handle, _clock) = lab("router").await?;
    for (locale, lang) in [(Locale::En, "en"), (Locale::Ru, "ru")] {
        let failsafe = |action: &str| {
            env.kcc(&[
                "--lang",
                lang,
                "--confirm-destructive",
                "lab-1",
                "config",
                "failsafe",
                action,
            ])
        };
        let describe = |text: &str| {
            let run = env.kcc(&["system", "set-description", text])?;
            assert_eq!(run.code, 0_i32, "{run:?}");
            Ok::<(), Box<dyn Error>>(())
        };
        let kept = format!("kept-{lang}");
        let dropped = format!("dropped-{lang}");
        says(&failsafe("arm")?, locale, keys::CLI_FAILSAFE_RUNNING);
        let alive = env.kcc(&["--lang", lang, "config", "keep-alive"])?;
        says(&alive, locale, keys::CLI_FAILSAFE_RUNNING);
        describe(&kept)?;
        says(&failsafe("commit")?, locale, keys::CLI_FAILSAFE_COMMITTED);
        assert!(handle.startup_config_text().contains(&kept), "commit saved");
        says(&failsafe("arm")?, locale, keys::CLI_FAILSAFE_RUNNING);
        describe(&dropped)?;
        says(
            &failsafe("rollback")?,
            locale,
            keys::CLI_FAILSAFE_ROLLED_BACK,
        );
        let running = handle.running_config_text();
        assert!(
            running.contains(&kept) && !running.contains(&dropped),
            "rollback restored the saved configuration: {running}"
        );
    }
    handle.shutdown().await?;
    Ok(())
}

/// Scheduled-reboot commit saves the running configuration and cancels the reboot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduled_reboot_commit_saves_and_disarms() -> TestResult {
    let (env, handle, clock) = lab("extender").await?;
    let arm = env.kcc(&[
        "--confirm-destructive",
        "lab-1",
        "config",
        "failsafe",
        "arm",
    ])?;
    says(&arm, Locale::En, keys::CLI_FAILSAFE_RUNNING);
    let changed = env.kcc(&["system", "set-description", "kept-after-commit"])?;
    assert_eq!(changed.code, 0_i32, "{changed:?}");
    let committed = env.kcc(&["config", "failsafe", "commit"])?;
    says(&committed, Locale::En, keys::CLI_FAILSAFE_COMMITTED);
    assert!(
        handle.startup_config_text().contains("kept-after-commit"),
        "scheduled commit must save the running configuration"
    );
    let commands = handle
        .request_log()
        .into_iter()
        .filter_map(|request| request.command().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(
        commands.iter().any(|command| command == "no system reboot"),
        "scheduled commit must cancel the reboot: {commands:?}"
    );
    assert!(
        !commands
            .iter()
            .any(|command| command == "system configuration fail-safe commit"),
        "scheduled commit must not use native fail-safe commit: {commands:?}"
    );
    let changed_again = env.kcc(&["system", "set-description", "still-running"])?;
    assert_eq!(changed_again.code, 0_i32, "{changed_again:?}");
    clock.advance(Duration::from_secs(301));
    let state = env.kcc(&["config", "state"])?;
    assert_eq!(state.code, 0_i32, "{state:?}");
    assert!(
        handle.running_config_text().contains("still-running"),
        "cancelled reboot must not restore startup"
    );
    handle.shutdown().await?;
    Ok(())
}

/// Scheduled-reboot rollback reboots at once into the saved configuration and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scheduled_reboot_rollback_reboots_at_once() -> TestResult {
    let (env, handle, _clock) = lab("extender").await?;
    let arm = env.kcc(&[
        "--confirm-destructive",
        "lab-1",
        "config",
        "failsafe",
        "arm",
    ])?;
    says(&arm, Locale::En, keys::CLI_FAILSAFE_RUNNING);
    let changed = env.kcc(&["system", "set-description", "discard-on-rollback"])?;
    assert_eq!(changed.code, 0_i32, "{changed:?}");
    let rolled_back = env.kcc(&[
        "--confirm-destructive",
        "lab-1",
        "config",
        "failsafe",
        "rollback",
    ])?;
    says(&rolled_back, Locale::En, keys::FAILSAFE_ROLLBACK_REBOOTING);
    assert!(
        !handle.running_config_text().contains("discard-on-rollback"),
        "scheduled rollback must restore startup configuration"
    );
    let commands = handle
        .request_log()
        .into_iter()
        .filter_map(|request| request.command().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(
        commands.iter().any(|command| command == "system reboot")
            && !commands
                .iter()
                .any(|command| command == "system configuration fail-safe rollback"),
        "scheduled rollback must reboot, not use the native rollback: {commands:?}"
    );
    handle.shutdown().await?;
    Ok(())
}

/// Router-mode commit retains the native fail-safe command and never uses reboot fallback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_commit_remains_native() -> TestResult {
    let (env, handle, _clock) = lab("router").await?;
    let arm = env.kcc(&[
        "--confirm-destructive",
        "lab-1",
        "config",
        "failsafe",
        "arm",
    ])?;
    says(&arm, Locale::En, keys::CLI_FAILSAFE_RUNNING);
    let committed = env.kcc(&["config", "failsafe", "commit"])?;
    says(&committed, Locale::En, keys::CLI_FAILSAFE_COMMITTED);
    let commands = handle
        .request_log()
        .into_iter()
        .filter_map(|request| request.command().map(str::to_owned))
        .collect::<Vec<_>>();
    assert!(
        commands
            .iter()
            .any(|command| command == "system configuration fail-safe commit"),
        "router commit must remain native: {commands:?}"
    );
    assert!(
        !commands
            .iter()
            .any(|command| command.contains("system reboot")),
        "router commit must not use scheduled reboot: {commands:?}"
    );
    handle.shutdown().await?;
    Ok(())
}

/// A reboot says the router is carrying it out, in English and German.
///
/// A factory reset shares the headline, but the fake router refuses
/// `system configuration factory-reset`, so no test drives one to success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reboot_says_the_router_is_carrying_it_out() -> TestResult {
    let (env, handle, _clock) = lab("router").await?;
    for (locale, lang) in [(Locale::En, "en"), (Locale::De, "de")] {
        let run = env.kcc(&[
            "--lang",
            lang,
            "--confirm-destructive",
            "lab-1",
            "system",
            "reboot",
        ])?;
        says(&run, locale, keys::CLI_DONE_TERMINAL);
    }
    handle.shutdown().await?;
    Ok(())
}
