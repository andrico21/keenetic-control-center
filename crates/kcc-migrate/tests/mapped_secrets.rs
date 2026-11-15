//! Integration coverage for mappings on secret-bearing lines and on Wi-Fi access points.

extern crate alloc;

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the mapping contract"
    )]

    use alloc::collections::{BTreeMap, BTreeSet};
    use core::error::Error;

    use kcc_config::config_text::parse;
    use kcc_migrate::{
        maps::{InterfaceMap, MapEntry, PortMap, RadioMap},
        rules::{
            self, ClassificationChoices, ClassificationTarget, ClassifiedItem, Disposition,
            InterfaceInventory,
        },
    };
    use secrecy::ExposeSecret as _;

    /// A run-time dummy `ns3` payload, never a committed literal.
    fn blob() -> String {
        "Zq".repeat(15)
    }

    /// Radio and logical-interface mapping decisions of one classification.
    struct Mappings<'entries> {
        /// Radio mappings.
        radios: &'entries [(&'entries str, &'entries str)],
        /// Logical-interface mappings.
        interfaces: &'entries [(&'entries str, &'entries str)],
    }

    /// Converts `(source, target)` pairs into mapping decisions.
    fn entries(pairs: &[(&str, &str)]) -> Vec<MapEntry> {
        pairs
            .iter()
            .map(|(source, target)| MapEntry::new((*source).to_owned(), Some((*target).to_owned())))
            .collect()
    }

    /// Classifies `source` against `target` with the WireGuard component installed.
    fn classify(
        source: &str,
        target: &str,
        mappings: &Mappings<'_>,
        overwrites: &[&str],
    ) -> Result<Vec<ClassifiedItem>, Box<dyn Error>> {
        let source_ast = parse(source)?;
        let target_ast = parse(target)?;
        let installed = BTreeSet::from(["wireguard".to_owned()]);
        let mut radio_map = RadioMap::default();
        radio_map.entries = entries(mappings.radios);
        let mut interface_map = InterfaceMap::default();
        interface_map.entries = entries(mappings.interfaces);
        let port_map = PortMap::default();
        let passwords = BTreeMap::new();
        let overwrite_scalars = overwrites.iter().map(|key| (*key).to_owned()).collect();
        let choices = ClassificationChoices::new(
            &port_map,
            &radio_map,
            &interface_map,
            &passwords,
            &overwrite_scalars,
        );
        let target_view = ClassificationTarget::new(
            None,
            &target_ast,
            &installed,
            None,
            InterfaceInventory::Unavailable,
        );
        Ok(rules::classify(&source_ast, target_view, &choices)?)
    }

    /// The commands each item sends, in source order.
    fn outputs(items: &[ClassifiedItem]) -> Vec<Option<String>> {
        items
            .iter()
            .map(|item| {
                item.output
                    .as_ref()
                    .map(|output| output.expose_secret().to_owned())
            })
            .collect()
    }

    /// G-01: a mapped access point's `wpa-psk ns3` line lands on the mapped access point.
    ///
    /// Its redacted twin shows the mapped name and no secret, and Debug output hides it too.
    #[test]
    fn mapped_access_point_keeps_its_psk() -> Result<(), Box<dyn Error>> {
        let secret = blob();
        let source = format!(
            "interface WifiMaster0/AccessPoint0\n ssid Office\n authentication wpa-psk ns3 {secret}\n"
        );
        let mappings = Mappings {
            radios: &[],
            interfaces: &[("WifiMaster0/AccessPoint0", "WifiMaster1/AccessPoint2")],
        };

        let items = classify(&source, "", &mappings, &[])?;

        assert_eq!(
            outputs(&items),
            [
                Some("interface WifiMaster1/AccessPoint2 ssid Office".to_owned()),
                Some(format!(
                    "interface WifiMaster1/AccessPoint2 authentication wpa-psk ns3 {secret}"
                )),
            ]
        );
        let [_ssid, psk] = items.as_slice() else {
            return Err("expected two items".into());
        };
        assert_eq!(psk.disposition, Disposition::Remap);
        assert_eq!(
            psk.after.as_deref(),
            Some("interface WifiMaster1/AccessPoint2 authentication wpa-psk ns3 <redacted>")
        );
        assert!(!format!("{psk:?}").contains(&secret));
        Ok(())
    }

    /// G-01: a mapped WireGuard interface keeps its private key on the mapped name.
    #[test]
    fn mapped_wireguard_interface_keeps_its_private_key() -> Result<(), Box<dyn Error>> {
        let key = blob();
        let source = format!("interface Wireguard0 wireguard private-key {key}\n");
        let mappings = Mappings {
            radios: &[],
            interfaces: &[("Wireguard0", "Wireguard2")],
        };

        let items = classify(&source, "", &mappings, &[])?;

        assert_eq!(
            outputs(&items),
            [Some(format!(
                "interface Wireguard2 wireguard private-key {key}"
            ))]
        );
        assert_eq!(
            items.first().and_then(|item| item.after.as_deref()),
            Some("interface Wireguard2 wireguard private-key <redacted>")
        );
        Ok(())
    }

    /// G-01: a secret line on an unmapped interface is sent unchanged.
    #[test]
    fn unmapped_secret_line_is_unchanged() -> Result<(), Box<dyn Error>> {
        let secret = blob();
        let source = format!("interface PPPoE0 authentication password ns3 {secret}\n");
        let mappings = Mappings {
            radios: &[],
            interfaces: &[("Bridge0", "Bridge2")],
        };

        let items = classify(&source, "", &mappings, &[])?;

        assert_eq!(outputs(&items), [Some(source.trim_end().to_owned())]);
        assert_eq!(
            items.first().map(|item| item.disposition),
            Some(Disposition::Copy)
        );
        Ok(())
    }

    /// G-01: a mapped secret line that would replace a different target secret is a
    /// conflict until the operator chooses to overwrite it.
    #[test]
    fn mapped_secret_line_runs_the_scalar_conflict_check() -> Result<(), Box<dyn Error>> {
        let secret = blob();
        let source = format!("interface PPPoE0 authentication password ns3 {secret}\n");
        let target = format!(
            "interface PPPoE1 authentication password ns3 {}\n",
            "Yx".repeat(15)
        );
        let mappings = Mappings {
            radios: &[],
            interfaces: &[("PPPoE0", "PPPoE1")],
        };

        let conflict = classify(&source, &target, &mappings, &[])?;
        let overwrite = classify(
            &source,
            &target,
            &mappings,
            &["interface PPPoE0 authentication password ns3"],
        )?;

        assert_eq!(
            conflict.first().map(|item| item.disposition),
            Some(Disposition::Conflict)
        );
        assert_eq!(
            outputs(&overwrite),
            [Some(format!(
                "interface PPPoE1 authentication password ns3 {secret}"
            ))]
        );
        Ok(())
    }

    /// H4a: a radio mapping moves the SSID, PSK and schedule lines of the radio's access
    /// points, and its own radio line.
    #[test]
    fn radio_mapping_moves_its_access_points() -> Result<(), Box<dyn Error>> {
        let secret = blob();
        let source = format!(
            "interface WifiMaster0\n channel 6\ninterface WifiMaster0/AccessPoint1\n ssid Office\n authentication wpa-psk ns3 {secret}\n schedule WorkHours\n"
        );
        let mappings = Mappings {
            radios: &[("WifiMaster0", "WifiMaster1")],
            interfaces: &[],
        };

        let items = classify(&source, "", &mappings, &[])?;

        assert_eq!(
            outputs(&items),
            [
                Some("interface WifiMaster1 channel 6".to_owned()),
                Some("interface WifiMaster1/AccessPoint1 ssid Office".to_owned()),
                Some(format!(
                    "interface WifiMaster1/AccessPoint1 authentication wpa-psk ns3 {secret}"
                )),
                Some("interface WifiMaster1/AccessPoint1 schedule WorkHours".to_owned()),
            ]
        );
        assert!(
            items
                .iter()
                .all(|item| item.disposition == Disposition::Remap)
        );
        Ok(())
    }
}
