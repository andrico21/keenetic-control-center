//! Hermetic proof that the hash probe cleans up on every path and checks its control.
#![expect(clippy::panic_in_result_fn, reason = "probe tests fail by asserting")]

use core::error::Error;

use kcc_app::settings::OutboundConfig;
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle,
    capture::{Connection, connect},
    model::{Model, Profile},
};
use secrecy::SecretString;

use super::{
    TestResult,
    probe::{self, ControlRefused, PROBE_USER, Probe, Realms},
};

/// Fail-safe arm and disarm lines around the probe.
const ARM: &str = "system configuration fail-safe timer reboot 900";
/// See [`ARM`].
const DISARM: &str = "no system configuration fail-safe timer";

/// A KN-1811 fake that already knows the probe account, so the fake applies its hash.
struct Lab {
    /// Router origin.
    url: String,
    /// Router handle.
    handle: Handle,
    /// The administrator connection the rehearsal admitted.
    admin: Connection,
    /// Outbound policy admitting the fake on loopback.
    outbound: OutboundConfig,
}

/// Starts the fake with `faults` and connects as the administrator.
// NOT cancel-safe: starts a background router.
async fn lab(faults: FaultInjection) -> Result<Lab, Box<dyn Error>> {
    let (address, handle) = FakeRouter::builder(Profile::latest(Model::Kn1811))
        .user(DEFAULT_LOGIN, DEFAULT_PASSWORD, ["cli", "http-proxy"])
        .user(PROBE_USER, format!("{:x}", 0x5eed_u32), ["readonly"])
        .faults(faults)
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let url = format!("http://{address}");
    let admin = connect(
        url.parse()?,
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
        true,
    )
    .await?;
    let mut outbound = OutboundConfig::default();
    outbound.allow_loopback = true;
    Ok(Lab {
        url,
        handle,
        admin,
        outbound,
    })
}

impl Lab {
    /// The probe's view of this lab.
    fn probe(&self) -> Probe<'_> {
        Probe {
            client: &self.admin.client,
            url: &self.url,
            outbound: &self.outbound,
        }
    }

    /// Parser lines the router received.
    fn commands(&self) -> Vec<String> {
        self.handle
            .request_log()
            .iter()
            .filter_map(|record| record.command().map(ToOwned::to_owned))
            .collect()
    }
}

/// A cross-model probe: the source realm is another model's.
const fn cross_model() -> Realms<'static> {
    Realms {
        source: Model::Kn1010.realm(),
        target: Model::Kn1811.realm(),
    }
}

/// Asserts the probe ran under the armed timer and removed its account.
fn assert_cleaned_up(commands: &[String]) {
    let removal = format!("no user {PROBE_USER}");
    assert_eq!(
        commands.first().map(String::as_str),
        Some(ARM),
        "timer not armed first"
    );
    assert!(
        commands.contains(&removal),
        "the probe account was left behind"
    );
    assert_eq!(
        commands.last().map(String::as_str),
        Some(DISARM),
        "timer not disarmed last"
    );
}

/// The control accepts the target-realm hash and the source-realm hash is recorded.
#[tokio::test]
async fn probe_reports_the_source_realm_with_an_accepted_control() -> TestResult {
    let lab = lab(FaultInjection::default()).await?;
    let observed = probe::password_hash(&lab.probe(), cross_model()).await?;
    assert!(
        !observed.source_accepted,
        "another model's realm was accepted"
    );
    assert_cleaned_up(&lab.commands());
    lab.handle.shutdown().await?;
    Ok(())
}

/// T-09: a probe command that fails midway still removes the probe account.
///
/// Every probe write happens inside the armed fail-safe timer.
#[tokio::test]
async fn probe_failure_midway_still_removes_the_account_under_the_timer() -> TestResult {
    let lab = lab(FaultInjection::default().fail_parse_matching("tag readonly", 1)).await?;
    let outcome = probe::password_hash(&lab.probe(), cross_model()).await;
    assert!(outcome.is_err(), "the injected failure was swallowed");
    assert_cleaned_up(&lab.commands());
    lab.handle.shutdown().await?;
    Ok(())
}

/// T-09: a refused target-realm control fails the probe.
///
/// The probe no longer records an uninformative source-realm result.
#[tokio::test]
async fn refused_target_realm_control_fails_the_probe() -> TestResult {
    let lab = lab(FaultInjection::default()).await?;
    let realms = Realms {
        source: Model::Kn1010.realm(),
        target: Model::Kn3810.realm(),
    };
    let refusal = probe::password_hash(&lab.probe(), realms)
        .await
        .err()
        .and_then(|error| error.downcast_ref::<ControlRefused>().copied());
    assert_eq!(refusal, Some(ControlRefused));
    assert_cleaned_up(&lab.commands());
    lab.handle.shutdown().await?;
    Ok(())
}
