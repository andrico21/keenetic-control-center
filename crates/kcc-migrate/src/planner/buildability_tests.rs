//! Planner/applier agreement over the shared migration matrix sources.

#[path = "../../tests/support/matrix_cases.rs"]
#[expect(
    dead_code,
    reason = "matrix source definitions also serve the integration runner"
)]
mod cases;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test contracts"
)]
mod tests {
    use core::error::Error;

    use kcc_rci::{auth::Credentials, version::FirmwareVersion};
    use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, outbound::loopback_client};
    use secrecy::{ExposeSecret as _, SecretString};

    use super::cases::{GIGA_43_FILE, Source, Target};
    use crate::{
        apply::command,
        inventory::{InventoryClient, TargetInventory},
        planner::{Choices, MigrationMaps, Planner},
        rules::Disposition,
        source::SourceConfig,
    };

    /// Every copy/remap output must build, and the fixture must retain all supported leaves.
    #[tokio::test]
    async fn matrix_copy_and_remap_outputs_build() -> Result<(), Box<dyn Error>> {
        for target in Target::ALL {
            let (address, handle) = FakeRouter::builder(target.profile()?)
                .build()?
                .serve(([127, 0, 0, 1], 0).into())
                .await?;
            let client = InventoryClient::from_client(
                &loopback_client(
                    format!("http://{address}").parse()?,
                    Credentials::new(
                        DEFAULT_LOGIN.to_owned(),
                        SecretString::from(DEFAULT_PASSWORD.to_owned()),
                    ),
                )
                .await?,
            );
            let inventory =
                TargetInventory::collect(&client, Some("4.3.0".parse::<FirmwareVersion>()?))
                    .await?;
            for source in Source::ALL {
                let text = if source == Source::Giga43File {
                    GIGA_43_FILE.to_owned()
                } else {
                    source.seed_lines().join("\n")
                };
                let parsed = SourceConfig::from_bytes(text.as_bytes())?;
                let mut choices =
                    Choices::default().with_reconnect_url(format!("http://{address}"));
                drop(choices.new_passwords.insert(
                    "operator".to_owned(),
                    SecretString::from(format!("{}-replacement", source.name())),
                ));
                let before = handle.request_log().len();
                let plan = Planner::plan(&parsed, &inventory, &MigrationMaps::default(), &choices)?;
                assert_eq!(
                    handle.request_log().len(),
                    before,
                    "planning contacted the router"
                );
                assert_eq!(
                    plan.expected_lines.len(),
                    plan.items
                        .iter()
                        .filter(|item| matches!(
                            item.disposition,
                            Disposition::Copy | Disposition::Remap
                        ))
                        .count()
                );
                if source != Source::Giga43File {
                    assert_eq!(
                        plan.expected_lines.len(),
                        source.seed_lines().len(),
                        "{} -> {} dropped a supported source line",
                        source.name(),
                        target.name()
                    );
                }
                for (index, line) in plan.expected_lines.iter().enumerate() {
                    drop(
                        command::build(&inventory.catalog, line.expose_secret()).map_err(
                            |error| {
                                format!(
                                    "{} -> {} output {index}: {error}",
                                    source.name(),
                                    target.name()
                                )
                            },
                        )?,
                    );
                }
            }
            handle.shutdown().await?;
        }
        Ok(())
    }

    /// Unsupported syntax is excluded from all executable phases without router requests.
    #[tokio::test]
    async fn unsupported_line_never_reaches_router() -> Result<(), Box<dyn Error>> {
        let (address, handle) = FakeRouter::builder(Target::Ultra51.profile()?)
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let client = InventoryClient::from_client(
            &loopback_client(
                format!("http://{address}").parse()?,
                Credentials::new(
                    DEFAULT_LOGIN.to_owned(),
                    SecretString::from(DEFAULT_PASSWORD.to_owned()),
                ),
            )
            .await?,
        );
        let inventory = TargetInventory::collect(&client, Some("4.3.0".parse()?)).await?;
        let source = SourceConfig::from_bytes(b"interface Bridge9 security-level invented\n")?;
        let before = handle.request_log().len();
        let plan = Planner::plan(
            &source,
            &inventory,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;
        assert_eq!(plan.items.len(), 1);
        assert_eq!(
            plan.items.first().map(|item| item.disposition),
            Some(Disposition::Unsupported)
        );
        assert!(
            plan.expected_lines.is_empty(),
            "unsupported line entered verification"
        );
        assert!(
            plan.phases.additive.is_empty()
                && plan.phases.management.is_empty()
                && plan.phases.prune.is_empty(),
            "unsupported line entered execution"
        );
        assert_eq!(
            handle.request_log().len(),
            before,
            "unsupported line caused router requests"
        );
        handle.shutdown().await?;
        Ok(())
    }
}
