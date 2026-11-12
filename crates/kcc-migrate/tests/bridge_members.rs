//! Bridge-membership classification against the target interface inventory.

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::collections::{BTreeMap, BTreeSet};
    use core::error::Error;

    use kcc_config::config_text::parse;
    use kcc_migrate::{
        maps::{InterfaceMap, PortMap, RadioMap},
        rules::{
            ClassificationChoices, ClassificationTarget, ClassifiedItem, Disposition,
            InterfaceInventory, RuleEngine,
        },
    };

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
        Ok(RuleEngine::embedded()?.classify(&source, target_view, &choices)?)
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
