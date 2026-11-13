//! The "not saved yet" headline follows the router's unsaved flag.

use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, firmware_update::FirmwareUpdate, model::Profile};

use super::support::{Env, TestResult, router};

/// A command that sends no configuration says it is done; a curated write says its
/// change is not saved yet.
// NOT cancel-safe: fixture writes may apply before cancellation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headline_says_unsaved_only_when_the_router_has_unsaved_configuration() -> TestResult {
    let (address, handle) = FakeRouter::builder(Profile::default())
        .build()?
        .with_firmware_update(FirmwareUpdate::Current)
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab-1", address, &password))?;
    let not_saved = tr(Locale::En, keys::CLI_APPLIED, None);
    let done = tr(Locale::En, keys::CLI_DONE, None);

    let check = env.kcc(&["components", "check-update"])?;
    assert_eq!(check.code, 0_i32, "{check:?}");
    assert!(check.stdout.contains(&done), "{check:?}");
    assert!(
        !check.stdout.contains(&not_saved) && !check.stderr.contains(&not_saved),
        "{check:?}"
    );

    let write = env.kcc(&["system", "set-description", "unsaved-headline"])?;
    assert_eq!(write.code, 0_i32, "{write:?}");
    assert!(write.stdout.contains(&not_saved), "{write:?}");
    assert!(!write.stdout.contains(&done), "{write:?}");
    handle.shutdown().await?;
    Ok(())
}
