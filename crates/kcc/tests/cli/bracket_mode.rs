//! The recovery mechanism follows the router's reported mode; an undecidable router is refused.
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{FakeRouter, migration, model::Profile};

use super::support::{Env, TestResult, router};

/// Each reported mode picks its mechanism, and a router with neither a usable mode nor a
/// fail-safe timer receives nothing.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_mechanism_follows_the_reported_mode() -> TestResult {
    let timer = Some((
        "system configuration fail-safe timer reboot 300",
        "no system configuration fail-safe timer",
    ));
    let reboot = Some(("system reboot 300", "no system reboot"));
    let rows = [
        (Some("router"), false, timer),
        (Some("extender"), false, reboot),
        (Some("bridge"), false, None),
        (None, false, timer),
        (None, true, None),
    ];
    for (mode, omit_fail_safe, expected) in rows {
        let mut scenario = migration::Fixture::default();
        scenario.mode = mode.map(str::to_owned);
        scenario.omit_fail_safe = omit_fail_safe;
        let fake = FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario);
        let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
        let env = Env::new("")?;
        let password = env.write(
            "router.password",
            &['a', 'd', 'm', 'i', 'n'].iter().collect::<String>(),
        )?;
        env.write_config(&router("lab-1", address, &password))?;
        let run = env.kcc(&["--yes", "services", "port", "http", "8082"])?;
        let commands = handle
            .request_log()
            .iter()
            .filter_map(|record| record.command().map(str::to_owned))
            .collect::<Vec<_>>();
        let label = format!("{mode:?} omit={omit_fail_safe}: {commands:?}; {run:?}");
        if let Some((arm, disarm)) = expected {
            assert_eq!(run.code, 0_i32, "{label}");
            assert!(commands.iter().any(|line| line == arm), "{label}");
            assert!(commands.iter().any(|line| line == disarm), "{label}");
        } else {
            let message = tr(Locale::En, keys::MANAGEMENT_MODE_UNKNOWN, None);
            assert_eq!(run.code, 10_i32, "{label}");
            assert!(run.stderr.contains(&message), "{label}");
            assert!(commands.is_empty(), "nothing is sent: {label}");
            assert!(
                !handle.running_config_text().contains("port 8082"),
                "{label}"
            );
        }
        handle.shutdown().await?;
    }
    Ok(())
}
