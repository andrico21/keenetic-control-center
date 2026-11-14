//! Bridge-membership classification against the target interface inventory.

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::collections::{BTreeMap, BTreeSet};
    use core::{error::Error, net::SocketAddr, str::FromStr as _};

    use kcc_config::config_text::parse;
    use kcc_migrate::{
        inventory::{InventoryClient, TargetInventory, source_version},
        maps::{InterfaceMap, PortMap, RadioMap},
        planner::{Choices, MigrationMaps, Planner},
        rules::{
            ClassificationChoices, ClassificationTarget, ClassifiedItem, Disposition,
            InterfaceInventory, classify,
        },
        source::SourceConfig,
    };
    use kcc_rci::{RouterUrl, auth::Credentials};
    use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile};
    use secrecy::SecretString;

    /// Classifies source text against an optional target interface inventory and mapping.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates fixture errors"
    )]
    fn classify_source(
        source_text: &str,
        target_interfaces: Option<&BTreeSet<String>>,
        interface_map: &InterfaceMap,
    ) -> Result<Vec<ClassifiedItem>, Box<dyn Error>> {
        let source = parse(source_text)?;
        let target = parse("")?;
        let installed = BTreeSet::new();
        let port_map = PortMap::default();
        let radio_map = RadioMap::default();
        let passwords = BTreeMap::new();
        let overwrites = BTreeSet::new();
        let choices = ClassificationChoices::new(
            &port_map,
            &radio_map,
            interface_map,
            &passwords,
            &overwrites,
        );
        let target_view = ClassificationTarget::new(
            None,
            &target,
            &installed,
            None,
            InterfaceInventory::from(target_interfaces),
        );
        Ok(classify(&source, target_view, &choices)?)
    }

    /// Classifies one bridge member against an optional target interface inventory.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates fixture errors"
    )]
    fn classify_member(
        member: &str,
        target_interfaces: Option<&BTreeSet<String>>,
    ) -> Result<ClassifiedItem, Box<dyn Error>> {
        let source = format!("interface Bridge0 include {member}\n");
        let mut items = classify_source(&source, target_interfaces, &InterfaceMap::default())?;
        items
            .pop()
            .ok_or_else(|| "membership line was not classified".into())
    }

    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper reports a missing membership"
    )]
    fn membership<'items>(
        items: &'items [ClassifiedItem],
        member: &str,
    ) -> Result<&'items ClassifiedItem, Box<dyn Error>> {
        items
            .iter()
            .find(|item| item.before.ends_with(&format!("include {member}")))
            .ok_or_else(|| format!("membership for {member} was not classified").into())
    }

    /// A real read-only inventory of the default fake KN-1811, whose catalog cannot build
    /// `vlan-id` and whose interface list has no `Vlan5`.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates fixture errors"
    )]
    async fn fake_target() -> Result<TargetInventory, Box<dyn Error>> {
        let router = FakeRouter::builder(Profile::default()).build()?;
        let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let url = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let client = InventoryClient::connect(url, credentials).await?;
        let inventory = TargetInventory::collect(&client, Some(source_version("4.3.0")?)).await?;
        handle.shutdown().await?;
        Ok(inventory)
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    async fn a_member_the_plan_does_not_create_gets_no_include_line() -> Result<(), Box<dyn Error>>
    {
        let header = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\n";
        let bridge = "interface Bridge1\n include Vlan5\n!\n";
        let target = fake_target().await?;
        for (case, vlan) in [
            (
                "only context line unbuildable",
                "interface Vlan5\n vlan-id 5\n!\n",
            ),
            ("every Vlan5 line excluded", ""),
        ] {
            let source = SourceConfig::from_bytes(format!("{header}{vlan}{bridge}").as_bytes())?;
            let maps = MigrationMaps::default();
            let classified = Planner::classify(&source, &target, &maps, &Choices::default())?;
            let plan = Planner::plan(&source, &target, &maps, &Choices::default())?;

            let item = membership(&classified, "Vlan5")?;
            assert_eq!(item.disposition, Disposition::SkipHardware, "{case}");
            assert_eq!(item.rule_id, "hardware-missing-bridge-member", "{case}");
            let sent = plan
                .phases
                .additive
                .iter()
                .chain(&plan.phases.management)
                .map(|line| line.expose_command().to_owned())
                .collect::<Vec<_>>();
            assert!(
                !sent
                    .iter()
                    .any(|line| line == "interface Bridge1 include Vlan5"),
                "{case}: {sent:?}"
            );
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn present_bridge_member_remains_an_additive_copy() -> Result<(), Box<dyn Error>> {
        let member = "GigabitEthernet0/3";
        let interfaces = BTreeSet::from([member.to_owned()]);

        let item = classify_member(member, Some(&interfaces))?;

        assert_eq!(item.disposition, Disposition::Copy);
        assert_eq!(item.rule_id, "default-copy");
        assert!(item.output.is_some());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn logical_members_with_realistic_children_are_copied_after_creation()
    -> Result<(), Box<dyn Error>> {
        let source = concat!(
            "interface Vlan5\n",
            " vlan-id 5\n",
            " up\n",
            " ip address 192.0.2.1 255.255.255.0\n",
            "!\n",
            "interface Bridge1\n",
            " description local-segment\n",
            " include Vlan5\n",
            " up\n",
            "!\n",
            "interface Bridge2\n",
            " include Bridge1\n",
            "!\n",
        );

        let items = classify_source(source, Some(&BTreeSet::new()), &InterfaceMap::default())?;

        let vlan_membership = membership(&items, "Vlan5")?;
        let bridge_membership = membership(&items, "Bridge1")?;
        assert_eq!(vlan_membership.disposition, Disposition::Copy);
        assert_eq!(bridge_membership.disposition, Disposition::Copy);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn mapped_bridge_member_created_by_the_same_plan_is_copied() -> Result<(), Box<dyn Error>> {
        let source = "interface Vlan5\n vlan-id 5\n up\n!\ninterface Bridge1\n include Vlan5\n!\n";
        let interface_map = serde_json::from_value(serde_json::json!({
            "entries": [{"source": "Vlan5", "target": "Vlan7"}]
        }))?;

        let items = classify_source(source, Some(&BTreeSet::new()), &interface_map)?;

        let membership = membership(&items, "Vlan5")?;
        assert_eq!(membership.disposition, Disposition::Remap);
        assert_eq!(
            membership.after.as_deref(),
            Some("interface Bridge1 include Vlan7")
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn absent_physical_port_contexts_do_not_create_bridge_members() -> Result<(), Box<dyn Error>> {
        let source = concat!(
            "interface GigabitEthernet0/4\n",
            " description uplink\n",
            " up\n",
            "!\n",
            "interface FastEthernet0/1\n",
            "!\n",
            "interface Bridge0\n",
            " include GigabitEthernet0/4\n",
            " include FastEthernet0/1\n",
            "!\n",
        );

        let items = classify_source(source, Some(&BTreeSet::new()), &InterfaceMap::default())?;

        for member in ["GigabitEthernet0/4", "FastEthernet0/1"] {
            assert_eq!(
                membership(&items, member)?.disposition,
                Disposition::SkipHardware
            );
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn present_physical_port_with_children_remains_copyable() -> Result<(), Box<dyn Error>> {
        let member = "GigabitEthernet0/4";
        let source = concat!(
            "interface GigabitEthernet0/4\n",
            " description uplink\n",
            " up\n",
            "!\n",
            "interface Bridge0\n",
            " include GigabitEthernet0/4\n",
            "!\n",
        );
        let interfaces = BTreeSet::from([member.to_owned()]);

        let items = classify_source(source, Some(&interfaces), &InterfaceMap::default())?;

        assert_eq!(membership(&items, member)?.disposition, Disposition::Copy);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn skipped_interface_context_does_not_create_a_bridge_member() -> Result<(), Box<dyn Error>> {
        let source = concat!(
            "interface Vlan5\n",
            " usb device 1-1\n",
            "!\n",
            "interface Bridge0\n",
            " include Vlan5\n",
            "!\n",
        );

        let items = classify_source(source, Some(&BTreeSet::new()), &InterfaceMap::default())?;

        assert_eq!(
            membership(&items, "Vlan5")?.disposition,
            Disposition::SkipHardware
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn absent_bridge_member_is_skipped_as_target_hardware() -> Result<(), Box<dyn Error>> {
        let interfaces = BTreeSet::from(["GigabitEthernet0/3".to_owned()]);

        let item = classify_member("GigabitEthernet0/4", Some(&interfaces))?;

        assert_eq!(item.disposition, Disposition::SkipHardware);
        assert_eq!(item.rule_id, "hardware-missing-bridge-member");
        assert_eq!(item.reason_key, "migration-reason-hardware-interface");
        assert!(item.output.is_none());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the task contract"
    )]
    fn unreadable_target_interface_inventory_never_copies_membership() -> Result<(), Box<dyn Error>>
    {
        let item = classify_member("GigabitEthernet0/3", None)?;

        assert_eq!(item.disposition, Disposition::SkipHardware);
        assert_eq!(item.rule_id, "hardware-missing-bridge-member");
        assert!(item.output.is_none());
        Ok(())
    }
}
