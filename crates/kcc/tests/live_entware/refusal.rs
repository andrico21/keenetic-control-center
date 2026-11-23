//! Hermetic proofs of the live contract's refusals.
//!
//! Every suite skips with `live-skip:<reason>` when a variable is missing, refuses a
//! non-test profile before any contact and an unlisted serial after the identification
//! read alone; the setup suite refuses a drive the router does not offer.
#![expect(clippy::panic_in_result_fn, reason = "refusal tests fail by asserting")]

use alloc::collections::BTreeMap;
use std::{env, io::Read as _, process::Stdio};

use super::{
    TestResult,
    lab::{Lab, logged},
    live_gate::Refusal,
    probe,
    setup::{self, SetupRefusal},
    spawning, ssh,
};

/// The three live suites.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Suite {
    /// The read-only probe.
    Probe,
    /// The guided setup.
    Setup,
    /// The SSH enrolment and operations.
    Ssh,
}

impl Suite {
    /// Every suite.
    const ALL: [Self; 3] = [Self::Probe, Self::Setup, Self::Ssh];

    /// Runs the suite against `lab` with its variables plus `changes`.
    // NOT cancel-safe: the suites contact the fakes.
    pub(crate) async fn run(self, lab: &Lab, changes: &[(&str, &str)]) -> TestResult {
        let vars: BTreeMap<String, String> = lab.env(changes);
        let read = |name: &str| vars.get(name).cloned();
        let reach = lab.reach();
        match self {
            Self::Probe => probe::run(&read, &reach).await,
            Self::Setup => setup::run(&read, &reach).await,
            Self::Ssh => ssh::run(&read, &reach).await,
        }
    }
}

/// Runs `suite` with `changes` and requires a passing skip that logged `live-skip:<reason>`
/// without a single router request.
async fn assert_skip(
    lab: &Lab,
    suite: Suite,
    changes: &[(&str, &str)],
    reason: &str,
) -> TestResult {
    let before = lab.handle.request_count();
    let (outcome, log) = logged(suite.run(lab, changes)).await?;
    assert!(outcome.is_ok(), "{suite:?} {changes:?}: {outcome:?}");
    let line = format!("live-skip:{reason}");
    assert!(
        log.contains(&line),
        "{suite:?} {changes:?}: no {line} in {log}"
    );
    assert_eq!(
        lab.handle.request_count(),
        before,
        "{suite:?} {changes:?} contacted the router"
    );
    Ok(())
}

/// Todo 19: each missing router variable skips every suite, with its reason, before any
/// contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_router_variables_skip_every_suite_before_contact() -> TestResult {
    let lab = Lab::start(true).await?;
    for suite in Suite::ALL {
        for (name, reason) in [
            ("KCC_LIVE_URL", "kcc_live_url-unset"),
            ("KCC_LIVE_LOGIN", "kcc_live_login-unset"),
            ("KCC_LIVE_PASSWORD_FILE", "kcc_live_password_file-unset"),
            ("KCC_LIVE_ALLOW_SERIAL", "kcc_live_allow_serial-unset"),
            ("KCC_LIVE_TARGET_CONFIG", "kcc_live_target_config-unset"),
        ] {
            assert_skip(&lab, suite, &[(name, "")], reason).await?;
        }
    }
    lab.shutdown().await
}

/// Todo 19: the setup and SSH suites skip unless `KCC_LIVE_ALLOW_WRITE` is exactly `1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_suites_skip_without_allow_write() -> TestResult {
    let lab = Lab::start(true).await?;
    for suite in [Suite::Setup, Suite::Ssh] {
        for (value, reason) in [
            ("", "kcc_live_allow_write-unset"),
            ("0", "kcc_live_allow_write-not-1"),
            ("yes", "kcc_live_allow_write-not-1"),
        ] {
            assert_skip(&lab, suite, &[("KCC_LIVE_ALLOW_WRITE", value)], reason).await?;
        }
    }
    lab.shutdown().await
}

/// Todo 19: the setup suite skips without `KCC_LIVE_ENTWARE_SETUP=1` or without
/// `KCC_LIVE_ENTWARE_DRIVE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_skips_without_its_flag_or_drive() -> TestResult {
    let lab = Lab::start(true).await?;
    for (name, value, reason) in [
        ("KCC_LIVE_ENTWARE_SETUP", "", "kcc_live_entware_setup-unset"),
        (
            "KCC_LIVE_ENTWARE_SETUP",
            "0",
            "kcc_live_entware_setup-not-1",
        ),
        (
            "KCC_LIVE_ENTWARE_SETUP",
            "true",
            "kcc_live_entware_setup-not-1",
        ),
        ("KCC_LIVE_ENTWARE_DRIVE", "", "kcc_live_entware_drive-unset"),
    ] {
        assert_skip(&lab, Suite::Setup, &[(name, value)], reason).await?;
    }
    lab.shutdown().await
}

/// Todo 19: the SSH suite skips without `KCC_LIVE_ENTWARE_PASSWORD_FILE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ssh_skips_without_the_entware_password_file() -> TestResult {
    let lab = Lab::start(true).await?;
    assert_skip(
        &lab,
        Suite::Ssh,
        &[("KCC_LIVE_ENTWARE_PASSWORD_FILE", "")],
        "kcc_live_entware_password_file-unset",
    )
    .await?;
    lab.shutdown().await
}

/// Todo 19: a profile without `test_device = true` is refused by every suite before the
/// router receives a single request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_test_profiles_are_refused_before_contact() -> TestResult {
    let lab = Lab::start(false).await?;
    let before = lab.handle.request_count();
    for suite in Suite::ALL {
        let outcome = suite.run(&lab, &[]).await;
        let refusal = outcome
            .err()
            .and_then(|error| error.downcast_ref::<Refusal>().copied());
        assert_eq!(refusal, Some(Refusal::NotTestDevice), "{suite:?}");
        assert_eq!(lab.handle.request_count(), before, "{suite:?} contacted");
    }
    lab.shutdown().await
}

/// Todo 19: a serial outside `KCC_LIVE_ALLOW_SERIAL` is refused by every suite after the
/// identification read alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unlisted_serials_are_refused_after_the_identification_alone() -> TestResult {
    let lab = Lab::start(true).await?;
    for suite in Suite::ALL {
        let before = lab.handle.request_log().len();
        let outcome = suite
            .run(&lab, &[("KCC_LIVE_ALLOW_SERIAL", "S0000000000NOT")])
            .await;
        let refusal = outcome
            .err()
            .and_then(|error| error.downcast_ref::<Refusal>().copied());
        assert_eq!(refusal, Some(Refusal::SerialNotAllowed), "{suite:?}");
        let paths = lab
            .handle
            .request_log()
            .into_iter()
            .skip(before)
            .filter(|record| record.path() != "/auth")
            .map(|record| record.path().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(paths, ["/rci/show/identification"], "{suite:?}");
    }
    assert_eq!(lab.writes(), Vec::<String>::new(), "writes sent");
    lab.shutdown().await
}

/// Todo 19: the setup suite refuses a drive that is not one of the router's eligible
/// drives (the internal storage included) and sends no write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setup_refuses_a_drive_the_router_does_not_offer() -> TestResult {
    let lab = Lab::start(true).await?;
    for drive in ["spare-drive:/", "internal", "fixture-media"] {
        let outcome = Suite::Setup
            .run(&lab, &[("KCC_LIVE_ENTWARE_DRIVE", drive)])
            .await;
        let refusal = outcome
            .err()
            .and_then(|error| error.downcast_ref::<SetupRefusal>().copied());
        assert_eq!(refusal, Some(SetupRefusal::DriveNotEligible), "{drive}");
    }
    assert_eq!(lab.writes(), Vec::<String>::new(), "writes sent");
    assert_eq!(lab.commands(), Vec::<String>::new(), "parser lines sent");
    lab.shutdown().await
}

/// Todo 19: the default run lists exactly the three live suites as ignored, so none of
/// them runs without `--ignored`.
#[test]
fn only_the_three_live_suites_are_ignored() -> TestResult {
    let mut child = spawning::spawn(
        spawning::command(env::current_exe()?)
            .args(["--list", "--ignored", "--format", "terse"])
            .env_clear()
            .envs(env::var_os("SystemRoot").map(|root| ("SystemRoot", root)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null()),
    )?;
    let mut listed = String::new();
    let _: usize = child
        .stdout
        .take()
        .ok_or("stdout unavailable")?
        .read_to_string(&mut listed)?;
    assert!(child.wait()?.success(), "listing failed: {listed}");
    let mut names = listed
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .collect::<Vec<_>>();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "live_entware_probe",
            "live_entware_setup",
            "live_entware_ssh"
        ]
    );
    Ok(())
}
