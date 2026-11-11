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
            ClassificationChoices, ClassificationTarget, ClassifiedItem, Disposition, RuleEngine,
        },
    };

    /// Classifies one bridge member against an optional target interface inventory.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates fixture errors"
    )]
    fn classify_member(
        member: &str,
        target_interfaces: Option<&BTreeSet<String>>,
    ) -> Result<ClassifiedItem, Box<dyn Error>> {
        let source = parse(&format!("interface Bridge0 include {member}\n"))?;
        let target = parse("")?;
        let installed = BTreeSet::new();
        let port_map = PortMap::default();
        let radio_map = RadioMap::default();
        let interface_map = InterfaceMap::default();
        let passwords = BTreeMap::new();
        let overwrites = BTreeSet::new();
        let choices = ClassificationChoices::new(
            &port_map,
            &radio_map,
            &interface_map,
            &passwords,
            &overwrites,
        );
        let target_view = ClassificationTarget::new(None, &target, &installed, None)
            .with_interfaces(target_interfaces);
        let mut items = RuleEngine::embedded()?.classify(&source, target_view, &choices)?;
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
