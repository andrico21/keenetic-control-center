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
    fn bridge_member_created_by_the_same_plan_is_copied_after_creation()
    -> Result<(), Box<dyn Error>> {
        let source = "interface Vlan5\n!\ninterface Bridge1\n include Vlan5\n!\n";

        let items = classify_source(source, Some(&BTreeSet::new()), &InterfaceMap::default())?;

        let [created, membership] = items.as_slice() else {
            return Err(format!(
                "expected creation and membership, got {} items",
                items.len()
            )
            .into());
        };
        assert_eq!(created.disposition, Disposition::Copy);
        assert_eq!(membership.disposition, Disposition::Copy);
        assert!(created.source_index < membership.source_index);
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
        let source = "interface Vlan5\n!\ninterface Bridge1\n include Vlan5\n!\n";
        let interface_map = serde_json::from_value(serde_json::json!({
            "entries": [{"source": "Vlan5", "target": "Vlan7"}]
        }))?;

        let items = classify_source(source, Some(&BTreeSet::new()), &interface_map)?;

        let [_, membership] = items.as_slice() else {
            return Err(format!(
                "expected creation and membership, got {} items",
                items.len()
            )
            .into());
        };
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
