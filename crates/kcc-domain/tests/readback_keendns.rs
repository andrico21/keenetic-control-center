//! KeenDNS configuration rejects acknowledged parser no-ops.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration tests report failures through assertions"
)]
mod tests {
    use kcc_app::workflow::WorkflowError;
    use kcc_domain::keendns::{self, RemoteSecurityLevel};
    use kcc_testkit::FaultInjection;

    use crate::support::{Fixture, PROFILES, TestResult};

    /// Remote-access exposure must match the requested security level.
    #[tokio::test]
    async fn silent_cloud_level_names_failed_field() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn_with_faults(
                firmware,
                FaultInjection::default().silent_noop_path("parse"),
            )
            .await?;
            let operation = keendns::plan_cloud_security_level(
                fixture.context(),
                RemoteSecurityLevel::Private,
            )?;
            let mut changes = fixture.changes().await?;
            let outcome = changes
                .apply_cli(keendns::change_request(&operation)?)
                .await;
            assert!(
                matches!(&outcome, Err(WorkflowError::VerificationFailed { field }) if field.contains("security-level")),
                "ignored cloud level must fail verification: {outcome:?}"
            );
            drop(changes);
            fixture.shutdown().await?;
        }
        Ok(())
    }

    /// Remote settings verify successfully when the router applies them.
    #[tokio::test]
    async fn remote_settings_are_read_back() -> TestResult {
        for firmware in PROFILES {
            let fixture = Fixture::spawn(firmware).await?;
            let operations = [
                keendns::plan_cloud_security_level(
                    fixture.context(),
                    RemoteSecurityLevel::Private,
                )?,
                keendns::plan_book_name(fixture.context(), "readback67", "keenetic.link")?,
                keendns::plan_drop_name(fixture.context(), "readback67", "keenetic.link")?,
                keendns::plan_proxy(fixture.context(), "proxy67", true)?,
                keendns::plan_proxy_upstream(
                    fixture.context(),
                    "proxy67",
                    "http",
                    "192.0.2.67",
                    8_080,
                )?,
            ];
            for operation in operations {
                let mut changes = fixture.changes().await?;
                assert!(
                    changes
                        .apply_cli(keendns::change_request(&operation)?)
                        .await?
                        .unsaved
                );
            }
            fixture.shutdown().await?;
        }
        Ok(())
    }
}
