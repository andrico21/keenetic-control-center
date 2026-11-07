//! Integration coverage for pure preset planning.

extern crate alloc;

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the preset planning contract"
    )]

    use alloc::sync::Arc;
    use core::{error::Error, net::SocketAddr, str::FromStr as _};

    use kcc_config::config_text::{flatten, parse};
    use kcc_migrate::{
        inventory::{InventoryClient, TargetInventory, source_version},
        maps::MapEntry,
        planner::{Choices, MigrationMaps},
        presets::{
            groups::SettingsGroupEngine,
            model::{CaptureRequest, Preset, PresetSource, PresetSourceKind},
            plan::{PresetInput, PresetMode, PresetPlanError, plan},
        },
        rules::Disposition,
    };
    use kcc_rci::{RouterUrl, auth::Credentials};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
        model::{Firmware, Model, Profile},
    };
    use secrecy::SecretString;

    #[tokio::test]
    async fn merge_remaps_policy_and_marks_unbuildable_context_leaf_unsupported()
    -> Result<(), Box<dyn Error>> {
        let (target, handle) = inventory(Profile::latest(Model::Kn3810), "4.3.0").await?;
        let preset = captured(
            "dns-records-routing",
            "5.1.1",
            "ip host example.test 192.0.2.1\ndns-proxy route Allowed Policy0\nip policy Policy0\n permit\n",
        )?;
        let mut maps = MigrationMaps::default();
        drop(
            maps.policies
                .insert("Policy0".to_owned(), "Policy9".to_owned()),
        );

        let planned = plan(
            &preset,
            &target,
            PresetMode::Merge,
            &maps,
            &Choices::default(),
        )?;

        assert_eq!(planned.items.len(), 3);
        let [host, route, policy] = planned.items.as_slice() else {
            return Err("expected three planned items".into());
        };
        assert_eq!(host.disposition, Disposition::Copy);
        assert_eq!(route.disposition, Disposition::Unsupported);
        assert_eq!(route.expose_command(), None);
        assert_eq!(policy.disposition, Disposition::Unsupported);
        assert_eq!(policy.expose_command(), None);
        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn mirror_removes_buildable_target_only_lines_in_selected_groups()
    -> Result<(), Box<dyn Error>> {
        let router = FakeRouter::builder(Profile::latest(Model::Kn3810)).build()?;
        let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let client = client(address).await?;
        let _response = client.parse("service ssh").await?;
        let inventory_client = InventoryClient::from_client(&Arc::new(client));
        let target =
            TargetInventory::collect(&inventory_client, Some(source_version("4.3.0")?)).await?;
        let preset = captured("system-baseline", "5.1.1", "service telnet\n")?;

        let planned = plan(
            &preset,
            &target,
            PresetMode::Mirror,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;

        assert!(planned.items.iter().any(|item| {
            item.disposition == Disposition::Remap
                && item.expose_command() == Some("no service ssh")
        }));
        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn unresolved_mapping_and_realm_password_are_plan_inputs() -> Result<(), Box<dyn Error>> {
        let (target, handle) = inventory(Profile::latest(Model::Kn3810), "4.3.0").await?;
        let mut preset = captured(
            "router-users",
            "5.1.1",
            "user operator\n password md5 deadbeef\n",
        )?;
        preset.lines.extend(flatten(&parse(
            "interface Bridge9\n description migrated\n",
        )?));
        let mut maps = MigrationMaps::default();
        maps.interfaces
            .entries
            .push(MapEntry::new("Bridge9".to_owned(), None));

        let planned = plan(
            &preset,
            &target,
            PresetMode::Merge,
            &maps,
            &Choices::default(),
        )?;

        let password = planned.items.first().ok_or("missing password item")?;
        assert_eq!(
            password.needed_input,
            Some(PresetInput::RouterUserPassword {
                user: "operator".to_owned()
            })
        );
        assert!(planned.items.iter().any(|item| {
            item.needed_input
                == Some(PresetInput::Mapping {
                    source: "Bridge9".to_owned(),
                })
        }));
        assert!(!planned.is_ready());
        handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn firmware_and_documentation_tier_gates_precede_line_planning()
    -> Result<(), Box<dyn Error>> {
        let (old_target, old_handle) =
            inventory(Profile::new(Model::Kn1811, Firmware::V4_3)?, "4.3.0").await?;
        let preset = captured(
            "dns-records-routing",
            "5.1.1",
            "ip host example.test 192.0.2.1\n",
        )?;
        assert!(matches!(
            plan(
                &preset,
                &old_target,
                PresetMode::Merge,
                &MigrationMaps::default(),
                &Choices::default()
            ),
            Err(PresetPlanError::TargetFirmwareOlder)
        ));
        old_handle.shutdown().await?;

        let (documented, documented_handle) =
            inventory(Profile::new(Model::Kn1811, Firmware::V5_0)?, "4.3.0").await?;
        let documented_preset = captured(
            "dns-records-routing",
            "4.3.0",
            "ip host example.test 192.0.2.1\n",
        )?;
        assert!(matches!(
            plan(
                &documented_preset,
                &documented,
                PresetMode::Merge,
                &MigrationMaps::default(),
                &Choices::default()
            ),
            Err(PresetPlanError::DocumentationTierAcknowledgementRequired)
        ));
        let acknowledged = Choices::default().with_documentation_tier_acknowledgement();
        drop(plan(
            &documented_preset,
            &documented,
            PresetMode::Merge,
            &MigrationMaps::default(),
            &acknowledged,
        )?);
        documented_handle.shutdown().await?;
        Ok(())
    }

    fn captured(group: &str, firmware: &str, text: &str) -> Result<Preset, Box<dyn Error>> {
        let source = parse(text)?;
        let selection = SettingsGroupEngine::embedded()?.select(&source, &[group])?;
        Ok(Preset::captured(
            CaptureRequest::new(
                "planned".to_owned(),
                "Planned".to_owned(),
                String::new(),
                vec![group.to_owned()],
                PresetSource::new(
                    PresetSourceKind::File,
                    None,
                    "Keenetic Ultra".to_owned(),
                    firmware.to_owned(),
                    1_800_000_000,
                ),
                "tester".to_owned(),
            ),
            selection,
        ))
    }

    async fn inventory(
        profile: Profile,
        source_firmware: &str,
    ) -> Result<(TargetInventory, kcc_testkit::Handle), Box<dyn Error>> {
        let router = FakeRouter::builder(profile).build()?;
        let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let client = client(address).await?;
        let inventory_client = InventoryClient::from_client(&Arc::new(client));
        let target =
            TargetInventory::collect(&inventory_client, Some(source_version(source_firmware)?))
                .await?;
        Ok((target, handle))
    }

    async fn client(address: SocketAddr) -> Result<kcc_rci::RciClient, Box<dyn Error>> {
        let router = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        Ok(kcc_rci::RciClient::connect_with(
            router,
            credentials,
            kcc_rci::RciClientOptions::default()
                .with_outbound(kcc_rci::OutboundPolicy::default().with_loopback(true)),
        )
        .await?)
    }
}
