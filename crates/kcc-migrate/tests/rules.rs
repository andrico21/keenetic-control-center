//! Integration coverage for migration classification rules.

use alloc::collections::{BTreeMap, BTreeSet};
use core::{error::Error, str::FromStr as _};

extern crate alloc;

#[cfg(test)]
mod tests {
    #![expect(
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test fixtures assert one-item results and include assertion expressions"
    )]

    use kcc_catalog::Catalog;
    use kcc_config::config_text::{Ast, flatten, parse};
    use kcc_migrate::{
        maps::{InterfaceMap, PortMap, RadioMap},
        rules::{
            self, ClassificationChoices, ClassificationTarget, ClassifiedItem, Disposition,
            InterfaceInventory,
        },
    };
    use kcc_rci::version::FirmwareVersion;
    use proptest::{prelude::*, prop_assert, prop_assert_eq};
    use secrecy::{ExposeSecret, SecretString};

    use super::*;

    /// Classifies a fixture without catalog filtering or choices.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates fixture errors"
    )]
    fn classify(source: &str) -> Result<Vec<ClassifiedItem>, Box<dyn Error>> {
        classify_with(source, "", None, None, &[], &[], &[], &[], &[])
    }

    /// Classifies a fixture with explicit target facts and operator choices.
    #[expect(
        clippy::missing_errors_doc,
        clippy::too_many_arguments,
        reason = "integration-test helper exposes every independent engine input"
    )]
    fn classify_with(
        source: &str,
        target: &str,
        catalog: Option<&Catalog>,
        target_realm: Option<&str>,
        components: &[&str],
        ports: &[(&str, &str)],
        radios: &[(&str, &str)],
        interfaces: &[(&str, &str)],
        overwrites: &[&str],
    ) -> Result<Vec<ClassifiedItem>, Box<dyn Error>> {
        let source_ast = parse(source)?;
        let target_ast = parse(target)?;
        let installed = components
            .iter()
            .map(|component| (*component).to_owned())
            .collect();
        let port_map = map(ports);
        let radio_map = radio_map(radios);
        let interface_map = interface_map(interfaces);
        let passwords = BTreeMap::new();
        let overwrite_scalars = overwrites.iter().map(|key| (*key).to_owned()).collect();
        let target_interfaces = ports
            .iter()
            .chain(radios)
            .chain(interfaces)
            .map(|(_source, mapped)| (*mapped).to_owned())
            .collect();
        let target_view = ClassificationTarget::new(
            catalog,
            &target_ast,
            &installed,
            target_realm,
            InterfaceInventory::Available(&target_interfaces),
        );
        let choices = ClassificationChoices::new(
            &port_map,
            &radio_map,
            &interface_map,
            &passwords,
            &overwrite_scalars,
        );
        Ok(rules::classify(&source_ast, target_view, &choices)?)
    }

    /// Builds physical-port choices.
    fn map(entries: &[(&str, &str)]) -> PortMap {
        let serialized_entries = entries
            .iter()
            .map(|(source, target)| serde_json::json!({ "source": source, "target": target }))
            .collect::<Vec<_>>();
        serde_json::from_value(serde_json::json!({ "entries": serialized_entries }))
            .unwrap_or_default()
    }

    /// Builds radio choices.
    fn radio_map(entries: &[(&str, &str)]) -> RadioMap {
        let physical = map(entries);
        serde_json::from_value(serde_json::json!({ "entries": physical.entries }))
            .unwrap_or_default()
    }

    /// Builds logical-interface choices.
    fn interface_map(entries: &[(&str, &str)]) -> InterfaceMap {
        let physical = map(entries);
        serde_json::from_value(serde_json::json!({ "entries": physical.entries }))
            .unwrap_or_default()
    }

    /// Asserts a fixture selects one expected disposition and rule id.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn assert_rule(
        source: &str,
        disposition: Disposition,
        rule_id: &str,
    ) -> Result<(), Box<dyn Error>> {
        let items = classify(source)?;
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].disposition, disposition);
        assert_eq!(items[0].rule_id, rule_id);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_ndns_registration_and_booking_identity() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "ndns registration abc\n",
            Disposition::SkipIdentity,
            "identity-ndns-registration",
        )?;
        assert_rule(
            "ndns booking abc\n",
            Disposition::SkipIdentity,
            "identity-ndns-booking",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_cloud_identity() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "cloud enable\n",
            Disposition::SkipIdentity,
            "identity-cloud",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_acme_and_crypto_certificates() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "ip http ssl acme certificate cert0\n",
            Disposition::SkipIdentity,
            "identity-acme-certificates",
        )?;
        assert_rule(
            "crypto certificate cert0\n",
            Disposition::SkipIdentity,
            "identity-crypto-certificates",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_mws_pairing_and_acquire_identity() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "mws member Extender0 pairing enable\n",
            Disposition::SkipIdentity,
            "identity-mws-member-pairing",
        )?;
        assert_rule(
            "mws acquire Extender0\n",
            Disposition::SkipIdentity,
            "identity-mws-acquire",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_preflight_agreements() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "dpn accept\n",
            Disposition::SkipIdentity,
            "identity-dpn-accept",
        )?;
        assert_rule(
            "eula accept\n",
            Disposition::SkipIdentity,
            "identity-eula-accept",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_kernel_tunables() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "system set net.ipv4.ip_forward 1\n",
            Disposition::SkipIdentity,
            "identity-kernel-tunables",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_interface_and_factory_mac_identity() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "interface GigabitEthernet0/0 mac address 02:00:00:00:00:01\n",
            Disposition::SkipIdentity,
            "identity-interface-mac",
        )?;
        assert_rule(
            "mac address factory 02:00:00:00:00:01\n",
            Disposition::SkipIdentity,
            "identity-factory-mac",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_led_button_and_usb_power_hardware() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "system led power shutdown\n",
            Disposition::SkipHardware,
            "hardware-led",
        )?;
        assert_rule(
            "system button reset action reboot\n",
            Disposition::SkipHardware,
            "hardware-button",
        )?;
        assert_rule(
            "system usb power shutdown\n",
            Disposition::SkipHardware,
            "hardware-usb-power",
        )
    }

    /// Regression for todo 5: per-router Entware settings are never copied.
    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_entware_settings_as_hardware() -> Result<(), Box<dyn Error>> {
        let cases = [
            ("opkg disk X:/", "entware-disk"),
            ("opkg chroot", "entware-chroot"),
            ("opkg dns-override", "entware-dns-override"),
            ("opkg initrc /opt/etc/ndm/x", "entware-initrc"),
            ("opkg timezone auto", "entware-timezone"),
            ("opkg object-group fqdn y", "entware-object-group"),
        ];
        let source = cases.map(|(line, _id)| format!("{line}\n")).concat();
        let items = classify(&source)?;
        assert_eq!(items.len(), cases.len());
        for (item, (line, id)) in items.iter().zip(cases) {
            assert_eq!(item.disposition, Disposition::SkipHardware, "{line}");
            assert_eq!(item.rule_id, id, "{line}");
            assert_eq!(
                item.reason.key(),
                "migration-reason-hardware-entware",
                "{line}"
            );
            assert!(item.output.is_none(), "{line}");
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_radio_eeprom_and_wan_led_hardware() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "interface WifiMaster0 rf e2p 01ff\n",
            Disposition::SkipHardware,
            "hardware-radio-eeprom",
        )?;
        assert_rule(
            "interface GigabitEthernet0/0 led wan enable\n",
            Disposition::SkipHardware,
            "hardware-wan-led",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn skips_usb_device_ids_and_printer_bindings() -> Result<(), Box<dyn Error>> {
        assert_rule(
            "interface UsbModem0 usb device 1-1\n",
            Disposition::SkipHardware,
            "hardware-usb-device",
        )?;
        assert_rule(
            "printer Office bind usb0\n",
            Disposition::SkipHardware,
            "hardware-printer-binding",
        )
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn remaps_every_exact_mapped_reference_shape() -> Result<(), Box<dyn Error>> {
        let source = concat!(
            "interface Bridge0 include GigabitEthernet0/1\n",
            "interface Bridge1 inherit Bridge0\n",
            "interface PPPoE0 bind GigabitEthernet0/1\n",
            "interface Wireguard0 connect via Bridge0\n",
            "ip nat Bridge0\n",
            "ip access-group acl0 in Bridge0\n",
            "ip hotspot policy guest Bridge0\n",
            "ip static 203.0.113.8 255.255.255.255 Bridge0\n",
            "mws wlan guest bind WifiMaster0\n",
            "ip policy permit 100 Bridge0\n",
        );
        let items = classify_with(
            source,
            "",
            None,
            None,
            &[],
            &[("GigabitEthernet0/1", "GigabitEthernet0/2")],
            &[("WifiMaster0", "WifiMaster1")],
            &[("Bridge0", "Bridge2")],
            &[],
        )?;
        assert_eq!(items.len(), 10);
        assert!(
            items
                .iter()
                .all(|item| item.disposition == Disposition::Remap)
        );
        assert!(
            items
                .iter()
                .all(|item| item.rule_id == "remap-mapped-reference")
        );
        assert!(
            items
                .iter()
                .all(|item| item.after.as_deref().is_some_and(|after| {
                    !after.split_whitespace().any(|word| {
                        matches!(word, "GigabitEthernet0/1" | "WifiMaster0" | "Bridge0")
                    })
                }))
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn realm_bound_hash_needs_input_then_becomes_plain() -> Result<(), Box<dyn Error>> {
        let source = "! $$$ Model: Keenetic Giga\nuser admin password md5 secret-hash\n";
        let unresolved = classify_with(
            source,
            "",
            None,
            Some("Keenetic Ultra"),
            &[],
            &[],
            &[],
            &[],
            &[],
        )?;
        assert_eq!(unresolved[0].disposition, Disposition::NeedsInput);
        assert_eq!(unresolved[0].before, "user admin password md5 <redacted>");
        assert!(!format!("{:?}", unresolved[0]).contains("secret-hash"));

        let source_ast = parse(source)?;
        let target_ast = parse("")?;
        let installed = BTreeSet::new();
        let port_map = PortMap::default();
        let radio_map = RadioMap::default();
        let interface_map = InterfaceMap::default();
        let mut passwords = BTreeMap::new();
        drop(passwords.insert(
            "admin".to_owned(),
            SecretString::from("replacement".to_owned()),
        ));
        let overwrites = BTreeSet::new();
        let choices = ClassificationChoices::new(
            &port_map,
            &radio_map,
            &interface_map,
            &passwords,
            &overwrites,
        );
        let target_view = ClassificationTarget::new(
            None,
            &target_ast,
            &installed,
            Some("Keenetic Ultra"),
            InterfaceInventory::Unavailable,
        );
        let resolved = rules::classify(&source_ast, target_view, &choices)?;
        assert_eq!(resolved[0].disposition, Disposition::Remap);
        assert_eq!(
            resolved[0].after.as_deref(),
            Some("user admin password plain <redacted>")
        );
        assert_eq!(
            resolved[0].output.as_ref().map(ExposeSecret::expose_secret),
            Some("user admin password plain replacement")
        );
        Ok(())
    }

    /// G-21: the migration classifier and the preset classifier share one password
    /// replacement; an `ns3`-encoded realm-bound hash becomes a plain password word, never
    /// a plaintext password inside an `ns3` token.
    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn encoded_realm_bound_hash_becomes_a_plain_word() -> Result<(), Box<dyn Error>> {
        let source_ast =
            parse("! $$$ Model: Keenetic Giga\nuser admin password md5 ns3 encoded-hash\n")?;
        let target_ast = parse("")?;
        let installed = BTreeSet::new();
        let port_map = PortMap::default();
        let radio_map = RadioMap::default();
        let interface_map = InterfaceMap::default();
        let mut passwords = BTreeMap::new();
        drop(passwords.insert(
            "admin".to_owned(),
            SecretString::from("replacement".to_owned()),
        ));
        let overwrites = BTreeSet::new();
        let choices = ClassificationChoices::new(
            &port_map,
            &radio_map,
            &interface_map,
            &passwords,
            &overwrites,
        );
        let target_view = ClassificationTarget::new(
            None,
            &target_ast,
            &installed,
            Some("Keenetic Ultra"),
            InterfaceInventory::Unavailable,
        );
        let resolved = rules::classify(&source_ast, target_view, &choices)?;
        assert_eq!(
            resolved[0].output.as_ref().map(ExposeSecret::expose_secret),
            Some("user admin password plain replacement")
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn same_realm_hash_is_copied() -> Result<(), Box<dyn Error>> {
        let items = classify_with(
            "! $$$ Model: Keenetic Giga\nuser admin password nt secret-hash\n",
            "",
            None,
            Some("Keenetic Giga"),
            &[],
            &[],
            &[],
            &[],
            &[],
        )?;
        assert_eq!(items[0].disposition, Disposition::Copy);
        assert_eq!(items[0].rule_id, "default-copy");
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn ns3_and_wireguard_secrets_copy_without_report_leaks() -> Result<(), Box<dyn Error>> {
        let ns3 = classify("interface Bridge0 web-api password ns3 encoded-secret\n")?;
        assert_eq!(ns3[0].disposition, Disposition::Copy);
        assert_eq!(ns3[0].rule_id, "copy-ns3-secret");
        assert!(!ns3[0].before.contains("encoded-secret"));
        assert_eq!(
            ns3[0].output.as_ref().map(ExposeSecret::expose_secret),
            Some("interface Bridge0 web-api password ns3 encoded-secret")
        );

        let wireguard = classify_with(
            "interface Wireguard0 wireguard private-key private-secret\n",
            "",
            None,
            None,
            &["wireguard"],
            &[],
            &[],
            &[],
            &[],
        )?;
        assert_eq!(wireguard[0].disposition, Disposition::Copy);
        assert_eq!(wireguard[0].rule_id, "copy-wireguard-private-key");
        assert!(!wireguard[0].before.contains("private-secret"));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn missing_required_component_needs_install_input() -> Result<(), Box<dyn Error>> {
        let items = classify("interface Wireguard0 wireguard private-key private-secret\n")?;
        assert_eq!(items[0].disposition, Disposition::NeedsInput);
        assert_eq!(items[0].needed_input.as_deref(), Some("install wireguard"));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn scalar_difference_conflicts_unless_overwrite_is_selected() -> Result<(), Box<dyn Error>> {
        let conflict = classify_with(
            "system hostname source\n",
            "system hostname target\n",
            None,
            None,
            &[],
            &[],
            &[],
            &[],
            &[],
        )?;
        assert_eq!(conflict[0].disposition, Disposition::Conflict);
        assert_eq!(conflict[0].rule_id, "scalar-conflict");
        let overwrite = classify_with(
            "system hostname source\n",
            "system hostname target\n",
            None,
            None,
            &[],
            &[],
            &[],
            &[],
            &["system hostname"],
        )?;
        assert_eq!(overwrite[0].disposition, Disposition::Copy);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn explicit_rule_precedes_catalog_absence_and_unsupported_is_detected()
    -> Result<(), Box<dyn Error>> {
        let catalog =
            Catalog::for_firmware_and_model(FirmwareVersion::from_str("5.1.0")?, Some("KN-1811"))?;
        let explicit = classify_with(
            "system led power shutdown\n",
            "",
            Some(&catalog),
            None,
            &[],
            &[],
            &[],
            &[],
            &[],
        )?;
        assert_eq!(explicit[0].disposition, Disposition::SkipHardware);
        let unsupported = classify_with(
            "future command absent\n",
            "",
            Some(&catalog),
            None,
            &[],
            &[],
            &[],
            &[],
            &[],
        )?;
        assert_eq!(unsupported[0].disposition, Disposition::Unsupported);
        assert_eq!(unsupported[0].rule_id, "catalog-unsupported");
        Ok(())
    }

    /// Generates bounded arbitrary flat configuration text for the parser-backed property check.
    fn arbitrary_config() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::collection::vec("[a-z][a-z0-9]{0,7}", 1..6).prop_map(|words| words.join(" ")),
            0..32,
        )
        .prop_map(|lines| lines.join("\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn every_random_flattened_line_maps_exactly_once(source_text in arbitrary_config()) {
            let source = parse(&source_text)?;
            let target = Ast::default();
            let installed = BTreeSet::new();
            let port_map = PortMap::default();
            let radio_map = RadioMap::default();
            let interface_map = InterfaceMap::default();
            let passwords = BTreeMap::new();
            let overwrites = BTreeSet::new();
            let choices = ClassificationChoices::new(&port_map, &radio_map, &interface_map, &passwords, &overwrites);
            let target_view = ClassificationTarget::new(
                None,
                &target,
                &installed,
                None,
                InterfaceInventory::Unavailable,
            );
            let lines = flatten(&source);
            let items = rules::classify(&source, target_view, &choices)?;

            prop_assert_eq!(items.len(), lines.len());
            prop_assert_eq!(items.iter().map(|item| item.source_index).collect::<Vec<_>>(), (0..lines.len()).collect::<Vec<_>>());
            prop_assert!(items.iter().zip(lines.iter()).all(|(item, line)| item.line_no == line.line_no));
        }
    }
}
