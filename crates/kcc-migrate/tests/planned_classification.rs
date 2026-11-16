//! The classification every surface shows is the one the plan applies: lines the target
//! cannot build are unsupported in both, and settings the target already has send nothing.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration-test assertions define the task contract"
)]
mod tests {
    use core::{error::Error, net::SocketAddr, str::FromStr as _};

    use kcc_migrate::{
        inventory::{InventoryClient, TargetInventory, source_version},
        planner::{Choices, MigrationMaps, Planner},
        rules::Disposition,
        source::SourceConfig,
    };
    use kcc_rci::{RouterUrl, auth::Credentials};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile, outbound::loopback_client,
    };
    use secrecy::SecretString;

    /// One unsupported line, an unsupported setting of a logical interface, members
    /// created by the plan, present on and absent from the target, and a setting the target
    /// already has.
    const SOURCE: &str = concat!(
        "! $$$ Model: Keenetic Giga\n",
        "! $$$ Version: 4.3.0\n",
        "interface Vlan5\n",
        " description lab\n",
        " vlan-id 5\n",
        "!\n",
        "interface Bridge0\n",
        " include GigabitEthernet0/2\n",
        "!\n",
        "interface Bridge1\n",
        " include Vlan5\n",
        " include GigabitEthernet0/1\n",
        " include GigabitEthernet0/9\n",
        "!\n",
        "system f4bogus-command on\n",
    );

    /// A real read-only inventory of the default fake KN-1811.
    async fn inventory() -> Result<TargetInventory, Box<dyn Error>> {
        let router = FakeRouter::builder(Profile::default()).build()?;
        let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let url = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let client = InventoryClient::from_client(&loopback_client(url, credentials).await?);
        let inventory = TargetInventory::collect(&client, Some(source_version("4.3.0")?)).await?;
        handle.shutdown().await?;
        Ok(inventory)
    }

    #[tokio::test]
    async fn classification_is_the_plans_item_by_item() -> Result<(), Box<dyn Error>> {
        let target = inventory().await?;
        let source = SourceConfig::from_bytes(SOURCE.as_bytes())?;
        let (maps, choices) = (MigrationMaps::default(), Choices::default());

        let classified = Planner::classify(&source, &target, &maps, &choices)?;
        let plan = Planner::plan(&source, &target, &maps, &choices)?;

        let shown = classified
            .iter()
            .map(|item| {
                (
                    item.source_index,
                    item.disposition,
                    item.reason_key.as_str(),
                )
            })
            .collect::<Vec<_>>();
        let planned = plan
            .items
            .iter()
            .map(|item| {
                (
                    item.source_index,
                    item.disposition,
                    item.reason_key.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(shown, planned, "the shown classification is the plan's");
        let unsupported = "migration-reason-unsupported-command";
        assert_eq!(
            shown,
            [
                (
                    0,
                    Disposition::Copy,
                    "migration-reason-non-critical-description"
                ),
                (1, Disposition::Unsupported, unsupported),
                (2, Disposition::Copy, "migration-reason-default-copy"),
                (3, Disposition::Copy, "migration-reason-default-copy"),
                (4, Disposition::Copy, "migration-reason-default-copy"),
                (
                    5,
                    Disposition::SkipHardware,
                    "migration-reason-hardware-interface"
                ),
                (6, Disposition::Unsupported, unsupported),
            ],
            "{SOURCE}"
        );
        let sent = plan
            .phases
            .additive
            .iter()
            .chain(&plan.phases.management)
            .map(|line| line.source_index)
            .collect::<Vec<_>>();
        assert_eq!(sent, [0, 3, 4], "the target already has line 2");
        Ok(())
    }
}
