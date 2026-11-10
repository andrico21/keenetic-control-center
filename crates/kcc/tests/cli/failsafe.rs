//! The fail-safe timer's steps and the commands the router carries out by restarting say
//! what the router did: never the headline of an ordinary change or its advice to save.

use core::error::Error;

use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, migration, model::Profile};

use super::support::{Env, Run, TestResult, router};

/// A fake router in router mode, which has the native fail-safe timer, as `lab-1`.
async fn lab() -> Result<(Env, Handle), Box<dyn Error>> {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some("router".to_owned());
    let fake = FakeRouter::builder(Profile::default())
        .build()?
        .with_migration(scenario);
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    Ok((env, handle))
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
    let (env, handle) = lab().await?;
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

/// A reboot says the router is carrying it out, in English and German.
///
/// A factory reset shares the headline, but the fake router refuses
/// `system configuration factory-reset`, so no test drives one to success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reboot_says_the_router_is_carrying_it_out() -> TestResult {
    let (env, handle) = lab().await?;
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
