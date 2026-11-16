//! Integration coverage for migration sources, inventories, and map proposals.

use core::{error::Error, net::SocketAddr, str::FromStr as _};

#[cfg(test)]
mod tests {
    use kcc_migrate::{
        inventory::{InventoryClient, InventoryError, TargetInventory, source_version},
        maps::PortMap,
        source::{NeededInput, SourceConfig},
    };
    use kcc_rci::{RouterUrl, auth::Credentials, version::FirmwareVersion};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
        model::{Firmware, Model, Profile},
        outbound::loopback_client,
    };
    use secrecy::SecretString;

    use super::*;

    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn inventory_for(profile: Profile) -> Result<TargetInventory, Box<dyn Error>> {
        let router = FakeRouter::builder(profile).build()?;
        let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let url = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let client = InventoryClient::from_client(&loopback_client(url, credentials).await?);
        let result = TargetInventory::collect(&client, Some(source_version("4.3.0")?)).await;
        handle.shutdown().await?;
        Ok(result?)
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    async fn inventories_cover_all_fake_router_models() -> Result<(), Box<dyn Error>> {
        for model in Model::ALL {
            let inventory = inventory_for(Profile::latest(model)).await?;
            assert_eq!(inventory.info.hw_id(), Some(model.hw_id()));
            assert_ne!(inventory.ports.len(), 0);
            assert_eq!(inventory.realm.as_deref(), Some(model.realm()));
            assert!(!inventory.installed_components.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    async fn extra_source_lan_ports_are_unmapped() -> Result<(), Box<dyn Error>> {
        let source = inventory_for(Profile::latest(Model::Kn1010)).await?;
        let target = inventory_for(Profile::latest(Model::Kn3810)).await?;
        let proposed = PortMap::propose(&source.ports, &target.ports);
        let unmapped = proposed
            .entries
            .iter()
            .filter(|entry| entry.target.is_none())
            .count();
        assert_eq!(unmapped, 1);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn file_sources_map_models_and_request_missing_input() -> Result<(), Box<dyn Error>> {
        let giga = SourceConfig::from_bytes(
            b"! $$$ Model: Keenetic Giga\n! $$$ Version: 5.1.3\ninterface Bridge0\n!\n",
        )?;
        assert_eq!(giga.hw_id.as_deref(), Some("KN-1010"));

        let headerless = SourceConfig::from_bytes(b"interface Bridge0\n!\n")?;
        assert!(headerless.info.is_none());
        assert!(headerless.needs_input.contains(&NeededInput::Model));
        assert_eq!(NeededInput::Model.to_string(), "needs-input: model");
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    async fn firmware_ordering_rejects_only_older_targets() -> Result<(), Box<dyn Error>> {
        let old_profile = Profile::new(Model::Kn1811, Firmware::V4_3)?;
        let router = FakeRouter::builder(old_profile).build()?;
        let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let client = inventory_client(address).await?;
        let result = TargetInventory::collect(&client, Some(source_version("5.1.0")?)).await;
        assert!(matches!(
            result,
            Err(InventoryError::TargetFirmwareOlder {
                source_version: _,
                target_version: _,
            })
        ));
        handle.shutdown().await?;

        let new_profile = Profile::latest(Model::Kn1811);
        let newer = FakeRouter::builder(new_profile).build()?;
        let (new_address, new_handle) = newer.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let new_client = inventory_client(new_address).await?;
        let accepted =
            TargetInventory::collect(&new_client, Some(source_version("4.3.0")?)).await?;
        assert_eq!(
            accepted.info.firmware.map(FirmwareVersion::line),
            Some((5, 1))
        );
        new_handle.shutdown().await?;
        Ok(())
    }

    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates setup failures"
    )]
    async fn inventory_client(address: SocketAddr) -> Result<InventoryClient, Box<dyn Error>> {
        let url = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        Ok(InventoryClient::from_client(
            &loopback_client(url, credentials).await?,
        ))
    }
}
