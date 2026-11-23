//! Todo 16: `kcc router remove` warns before its confirmation while kcc's SSH key line is
//! still authorized on the router.

use kcc_i18n::keys;

use super::{
    lab::{ROUTER, SshLab, en, unconfirmed},
    support::TestResult,
};

/// Todo 16: the notice appears (before the confirmation refuses) only while the router's
/// Entware SSH enrolment is Active: not before the enrolment and not after a revoke.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn router_remove_warns_while_the_key_line_is_authorized() -> TestResult {
    let lab = SshLab::admin().await?;
    let notice = en(keys::CLI_ROUTER_REMOVE_SSH_ACTIVE, &[("router", ROUTER)]);

    let before = lab.run(&["router", "remove", ROUTER])?;
    lab.enrol()?;
    let enrolled = lab.run(&["router", "remove", ROUTER])?;
    drop(lab.json(&["entware", "ssh", "revoke"])?);
    let revoked = lab.run(&["router", "remove", ROUTER])?;

    for run in [&before, &enrolled, &revoked] {
        unconfirmed(run);
    }
    assert!(!before.stderr.contains(&notice), "{before:?}");
    assert!(enrolled.stderr.contains(&notice), "{enrolled:?}");
    assert!(!revoked.stderr.contains(&notice), "{revoked:?}");
    lab.shutdown().await
}
