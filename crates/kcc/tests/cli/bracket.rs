//! A management change runs inside the recovery timer of the router's mode, authorized by
//! the change's own permission; a router whose mode is undecidable receives nothing.
use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{
    DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle, migration, model::Profile,
};

use super::{
    permission_gates::{add_role, commands_after, edges},
    support::{Env, TestResult, router},
};

/// The scenario of a fake router reporting `mode`.
pub(crate) fn reporting(mode: &str) -> migration::Fixture {
    let mut scenario = migration::Fixture::default();
    scenario.mode = Some(mode.to_owned());
    scenario
}

/// Serves a fake router of `scenario` with `faults` and configures it as `lab-1` for the CLI
/// role `role`.
// NOT cancel-safe: the fixture owns router tasks once served.
pub(crate) async fn lab(
    scenario: migration::Fixture,
    faults: FaultInjection,
    role: &str,
) -> TestResult<(Env, Handle)> {
    let fake = FakeRouter::builder(Profile::default())
        .faults(faults)
        .build()?
        .with_migration(scenario);
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&format!(
        "[cli]\nrole = {role:?}\n{}",
        router("lab-1", address, &password)
    ))?;
    Ok((env, handle))
}

/// A raw change needs `RawRci`, not `Write`, for its whole bracket.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn management_bracket_without_write_permission() -> TestResult {
    let (env, handle) = lab(reporting("router"), FaultInjection::default(), "rawdes").await?;
    let permissions = [
        Permission::Read,
        Permission::RawRci,
        Permission::Destructive,
    ];
    add_role(&env, "rawdes", &permissions)?;

    let port = r#"{"port":8082}"#;
    let run = env.kcc(&["--yes", "rci", "post", "ip", "http", "port", "--data", port])?;

    let commands = commands_after(&handle, 0);
    let (arm, disarm) = edges("router");
    assert_eq!(run.code, 0_i32, "{run:?}");
    assert_eq!(commands.first().map(String::as_str), Some(arm), "{run:?}");
    assert_eq!(commands.last().map(String::as_str), Some(disarm), "{run:?}");
    assert!(!handle.recovery_armed(), "timer disarmed");
    handle.shutdown().await?;
    Ok(())
}

/// Curated VPN and WAN management commands run inside the router mode's timer.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn curated_management_commands_bracket() -> TestResult {
    let vpn = ["--yes", "vpn", "enable", "Bridge0", "off"];
    let wan = ["--yes", "wan", "priority", "Bridge0", "7"];
    for args in [&vpn[..], &wan] {
        let (env, handle) = lab(reporting("extender"), FaultInjection::default(), "admin").await?;

        let run = env.kcc(args)?;

        let commands = commands_after(&handle, 0);
        let (arm, disarm) = edges("extender");
        assert_eq!(run.code, 0_i32, "{args:?}: {run:?}");
        assert_eq!(commands.first().map(String::as_str), Some(arm), "{args:?}");
        assert_eq!(
            commands.last().map(String::as_str),
            Some(disarm),
            "{args:?}"
        );
        handle.shutdown().await?;
    }
    Ok(())
}

/// A router with neither a known mode nor a fail-safe timer is refused with exit 10 and
/// receives nothing.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_mechanism_follows_the_reported_mode() -> TestResult {
    for (mode, omit_fail_safe) in [(Some("bridge"), false), (None, true)] {
        let mut scenario = migration::Fixture::default();
        scenario.mode = mode.map(str::to_owned);
        scenario.omit_fail_safe = omit_fail_safe;
        let (env, handle) = lab(scenario, FaultInjection::default(), "admin").await?;

        let run = env.kcc(&["--yes", "services", "port", "ssh", "8082"])?;

        let label = format!("{mode:?} omit={omit_fail_safe}: {run:?}");
        let message = tr(Locale::En, keys::MANAGEMENT_MODE_UNKNOWN, None);
        assert_eq!(run.code, 10_i32, "{label}");
        assert!(run.stderr.contains(&message), "{label}");
        assert!(
            commands_after(&handle, 0).is_empty(),
            "nothing is sent: {label}"
        );
        assert!(
            !handle.running_config_text().contains("port 8082"),
            "{label}"
        );
        handle.shutdown().await?;
    }
    Ok(())
}
