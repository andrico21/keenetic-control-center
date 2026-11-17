//! Read-back of secret writes: the stored credential must change, never only be present.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

use kcc_app::workflow::{CliChangeRequest, WorkflowError};
use kcc_domain::{router_users, wan, wifi};
use kcc_rci::ObjectName;
use kcc_testkit::{DEFAULT_LOGIN, FaultInjection, model::Firmware};
use secrecy::SecretString;

mod support;

use crate::support::{Fixture, PROFILES, TestResult};

/// One secret write whose read-back is under test.
#[derive(Clone, Copy, Debug)]
enum Target {
    /// `user operator password plain ...`.
    RouterUser,
    /// `interface WifiMaster0/AccessPoint0 authentication wpa-psk ...`.
    WifiPsk,
    /// `interface PPPoE9 authentication password ...`.
    WanPassword,
}

impl Target {
    /// Every secret write that proves its change.
    const ALL: [Self; 3] = [Self::RouterUser, Self::WifiPsk, Self::WanPassword];

    /// The configuration words the credential is stored under: the field a failure names.
    const fn prefix(self) -> &'static str {
        match self {
            Self::RouterUser => "user operator password",
            Self::WifiPsk => "interface WifiMaster0/AccessPoint0 authentication wpa-psk",
            Self::WanPassword => "interface PPPoE9 authentication password",
        }
    }

    /// The parser line that sends `secret`, which is always one quoted word.
    fn line(self, secret: &str) -> String {
        match self {
            Self::RouterUser => format!("user operator password plain \"{secret}\""),
            Self::WifiPsk | Self::WanPassword => format!("{} \"{secret}\"", self.prefix()),
        }
    }

    /// Starts a fake router on which the write can be planned.
    async fn fixture(self, firmware: Firmware, faults: FaultInjection) -> TestResult<Fixture> {
        let fixture = Fixture::spawn_with_faults(firmware, faults).await?;
        if matches!(self, Self::WanPassword) {
            let name = wan_name()?;
            let create = wan::plan_create(fixture.context(), &name).await?;
            let mut changes = fixture.changes().await?;
            drop(
                changes
                    .apply_cli(wan::change_request(&name, &create)?)
                    .await?,
            );
        }
        Ok(fixture)
    }

    /// Plans the write of `typed`.
    async fn request(self, fixture: &Fixture, typed: &str) -> TestResult<CliChangeRequest> {
        let router = fixture.context();
        let secret = SecretString::from(typed.to_owned());
        Ok(match self {
            Self::RouterUser => {
                let own = router_users::protection::OwnLogins::new(DEFAULT_LOGIN, None)?;
                let plan = router_users::plan_password(router, "operator", &own, secret)?;
                router_users::change_request(&plan)?
            }
            Self::WifiPsk => {
                let name = ObjectName::try_from("WifiMaster0/AccessPoint0".to_owned())?;
                wifi::change_request(&name, &wifi::plan_wpa_psk(router, &name, secret)?)?
            }
            Self::WanPassword => {
                let name = wan_name()?;
                wan::change_request(&name, &wan::plan_password(router, &name, secret).await?)?
            }
        })
    }
}

/// The PPP connection the WAN write targets.
fn wan_name() -> TestResult<ObjectName> {
    Ok(ObjectName::try_from("PPPoE9".to_owned())?)
}

/// Whether `result` is the key-free failure naming `target`'s stored credential.
fn unchanged<T>(result: &Result<T, WorkflowError>, target: Target) -> bool {
    matches!(result, Err(WorkflowError::VerificationFailed { field }) if field == target.prefix())
}

/// A dummy credential built at run time.
fn secret(label: &str) -> String {
    [label, "credential", "67"].join("-")
}

/// C-22: a router that acknowledges a secret write but keeps the credential it already
/// stored fails verification; the failure names the command words, never a secret.
#[tokio::test]
async fn ignored_secret_write_over_a_stored_one_fails_verification() -> TestResult {
    let mut accepted = Vec::new();
    for firmware in PROFILES {
        for target in Target::ALL {
            let (previous, next) = (secret("previous"), secret("next"));
            let faults = FaultInjection::default().silent_noop_path(target.line(&next));
            let fixture = target.fixture(firmware, faults).await?;
            let mut changes = fixture.changes().await?;
            drop(
                changes
                    .apply_cli(target.request(&fixture, &previous).await?)
                    .await?,
            );
            let stored = fixture.handle().running_config_text();

            let result = changes
                .apply_cli(target.request(&fixture, &next).await?)
                .await;

            assert_eq!(fixture.handle().running_config_text(), stored, "{target:?}");
            if !unchanged(&result, target) {
                accepted.push(format!("{firmware:?} {target:?}"));
            }
            let text = format!("{result:?}");
            assert!(
                !text.contains(&previous) && !text.contains(&next),
                "{target:?}"
            );
            drop(changes);
            fixture.shutdown().await?;
        }
    }
    assert!(
        accepted.is_empty(),
        "unchanged credential accepted: {accepted:?}"
    );
    Ok(())
}

/// C-22: re-sending the stored value leaves the same stored credential (md5 and `ns3` are
/// deterministic), which cannot be told from an ignored write, so it fails the same way.
#[tokio::test]
async fn same_secret_rewrite_is_reported_as_unchanged() -> TestResult {
    let mut accepted = Vec::new();
    for firmware in PROFILES {
        for target in Target::ALL {
            let previous = secret("previous");
            let fixture = target.fixture(firmware, FaultInjection::default()).await?;
            let mut changes = fixture.changes().await?;
            drop(
                changes
                    .apply_cli(target.request(&fixture, &previous).await?)
                    .await?,
            );

            let result = changes
                .apply_cli(target.request(&fixture, &previous).await?)
                .await;

            if !unchanged(&result, target) {
                accepted.push(format!("{firmware:?} {target:?}"));
            }
            drop(changes);
            fixture.shutdown().await?;
        }
    }
    assert!(
        accepted.is_empty(),
        "unchanged credential accepted: {accepted:?}"
    );
    Ok(())
}

/// C-22: a first-time secret passes on presence, and a real change of a stored secret
/// passes, so the stricter check refuses only an unchanged credential.
#[tokio::test]
async fn first_secret_and_genuine_change_pass() -> TestResult {
    for firmware in PROFILES {
        for target in Target::ALL {
            let fixture = target.fixture(firmware, FaultInjection::default()).await?;
            let mut changes = fixture.changes().await?;

            let first = changes
                .apply_cli(target.request(&fixture, &secret("previous")).await?)
                .await;
            let second = changes
                .apply_cli(target.request(&fixture, &secret("next")).await?)
                .await;

            assert!(first.is_ok(), "{target:?}: {first:?}");
            assert!(second.is_ok(), "{target:?}: {second:?}");
            drop(changes);
            fixture.shutdown().await?;
        }
    }
    Ok(())
}

/// C-22: when the stored credential cannot be read before the write, nothing is sent:
/// the change could not be proven afterwards.
#[tokio::test]
async fn unreadable_baseline_sends_nothing() -> TestResult {
    for firmware in PROFILES {
        let target = Target::WifiPsk;
        let faults = FaultInjection::default().fail_read_matching("running-config.txt", 1);
        let fixture = target.fixture(firmware, faults).await?;
        let mut changes = fixture.changes().await?;

        let result = changes
            .apply_cli(target.request(&fixture, &secret("previous")).await?)
            .await;

        assert!(matches!(result, Err(WorkflowError::Rci(_))), "{result:?}");
        assert!(!fixture.handle().running_config_text().contains("wpa-psk"));
        drop(changes);
        fixture.shutdown().await?;
    }
    Ok(())
}
