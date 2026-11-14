//! An audit writer that dies on the bracket's first receipt still lets the CLI disarm.

#[path = "../serve_bracket/proxy.rs"]
mod proxy;

use std::fs;

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, model::Profile};

use self::proxy::Action;
use crate::{
    bracket::reporting,
    permission_gates::{commands_after, edges},
    support::{Env, TestResult, router},
};

/// The router-mode arm line, as the relay sees it.
const ARM: &[u8] = b"fail-safe timer reboot";

/// The writer's next append verifies a directory at its rotation path and fails, which
/// ends the writer: created once the arm passes, its receipt is that append.
// NOT cancel-safe: the fixture owns router and relay tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_dying_after_the_arm_still_disarms() -> TestResult {
    let fake = FakeRouter::builder(Profile::default())
        .build()?
        .with_migration(reporting("router"));
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let rotation = env.state_dir().join(format!("audit-{:020}.jsonl", 0_u64));
    let kill: Action =
        Box::new(move || Box::pin(async move { drop(fs::create_dir_all(rotation)) }));
    let relay = proxy::spawn(address, vec![(ARM, kill)]).await?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", relay, &password))?;

    let run = env.kcc(&["--yes", "services", "port", "http", "8082"])?;

    let commands = commands_after(&handle, 0);
    let (arm, disarm) = edges("router");
    assert_eq!(run.code, 1_i32, "the dead writer is the failure: {run:?}");
    assert_eq!(commands.first().map(String::as_str), Some(arm), "{run:?}");
    assert_eq!(commands.last().map(String::as_str), Some(disarm), "{run:?}");
    assert!(!handle.recovery_armed(), "the disarm was accepted");
    for key in [
        keys::MANAGEMENT_NOT_SENT_ARMED,
        keys::MANAGEMENT_DISARM_FAILED,
        keys::MANAGEMENT_OUTCOME_UNKNOWN_ARMED,
    ] {
        assert!(!run.stderr.contains(&tr(Locale::En, key, None)), "{run:?}");
    }
    handle.shutdown().await?;
    Ok(())
}
