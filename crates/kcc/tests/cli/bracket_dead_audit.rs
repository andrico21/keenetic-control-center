//! An audit writer that dies on the bracket's first receipt still lets the CLI disarm.

#[path = "../serve_bracket/proxy.rs"]
mod proxy;

use std::{fs::OpenOptions, io::Write as _, path::Path};

use kcc_app::{audit::AUDIT_FILE_NAME, persist::StateStore};
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

/// Appends a complete line that is not an audit entry to the log in `state`, under the
/// append lock, so the writer's next append reads it and fails.
fn poison(state: &Path) -> TestResult {
    let _lock = StateStore::open(state)?.lock(AUDIT_FILE_NAME)?;
    OpenOptions::new()
        .append(true)
        .open(state.join(AUDIT_FILE_NAME))?
        .write_all(b"not an entry\n")?;
    Ok(())
}

/// The writer's next append reads a last line that is not an entry and fails, which ends
/// the writer: written once the arm passes, its receipt is that append.
// NOT cancel-safe: the fixture owns router and relay tasks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_dying_after_the_arm_still_disarms() -> TestResult {
    let fake = FakeRouter::builder(Profile::default())
        .build()?
        .with_migration(reporting("router"));
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    let env = Env::new("")?;
    let state = env.state_dir();
    let kill: Action = Box::new(move || Box::pin(async move { drop(poison(&state)) }));
    let relay = proxy::spawn(address, vec![(ARM, kill)]).await?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", relay, &password))?;

    let run = env.kcc(&["--yes", "services", "port", "ssh", "8082"])?;

    let commands = commands_after(&handle, 0);
    let (arm, disarm) = edges("router");
    assert_eq!(run.code, 1_i32, "the dead writer is the failure: {run:?}");
    assert!(
        !run.stderr.contains("audit writer failed"),
        "stderr must not contain audit error when RUST_LOG is unset (todo 10): {run:?}"
    );
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
