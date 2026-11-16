//! Typed flattened CLI contracts, including parent context arguments.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test contracts"
)]
#[expect(clippy::panic_in_result_fn, reason = "assertions report test failures")]
mod tests {
    use core::error::Error;

    use kcc_rci::version::FirmwareVersion;
    use serde_json::json;

    use crate::{Catalog, RawAuthorization, ValidationIssue};

    /// Parent arguments select a context; leaf arguments retain their own typed object.
    #[test]
    fn context_leaves_and_alternatives_keep_typed_arguments() -> Result<(), Box<dyn Error>> {
        let catalog =
            Catalog::for_firmware_and_model("5.1.0".parse::<FirmwareVersion>()?, Some("KN-1811"))?;
        for (line, path, value) in [
            (
                "interface Bridge0 description guest",
                "interface description",
                json!({"description":"guest"}),
            ),
            (
                "interface Bridge0 security-level private",
                "interface security-level",
                json!({"level":"private"}),
            ),
            ("interface Bridge0 up", "interface up", json!({})),
            (
                "no interface Bridge0 description",
                "interface description",
                json!({"no":true}),
            ),
            (
                "ip dhcp pool guest range 192.0.2.10 20",
                "ip dhcp pool range",
                json!({"begin":"192.0.2.10", "size":20_i64}),
            ),
            (
                "ip dhcp pool guest range 192.0.2.10 192.0.2.30",
                "ip dhcp pool range",
                json!({"begin":"192.0.2.10", "end":"192.0.2.30"}),
            ),
            (
                "ip policy guest permit global Wireguard0 order 10",
                "ip policy permit",
                json!({"interface":"Wireguard0", "order":10_i64}),
            ),
            ("user operator tag cli", "user tag", json!({"tag":"cli"})),
            (
                "ip name-server 192.0.2.53",
                "ip name-server",
                json!({"address":"192.0.2.53"}),
            ),
            ("ip nat Bridge0", "ip nat", json!({"interface":"Bridge0"})),
            (
                "ip nat 192.0.2.0 255.255.255.0",
                "ip nat",
                json!({"address":"192.0.2.0", "mask":"255.255.255.0"}),
            ),
            (
                "ip route 198.51.100.0 255.255.255.0 192.0.2.1",
                "ip route",
                json!({"network":"198.51.100.0", "mask":"255.255.255.0", "gateway":"192.0.2.1"}),
            ),
            (
                "ip dhcp host workstation",
                "ip dhcp host",
                json!({"host":"workstation"}),
            ),
            (
                "system description migration",
                "system description",
                json!({"description":"migration"}),
            ),
        ] {
            let result = catalog.validate_cli(line, RawAuthorization::default());
            let request = result.map_err(|issues| format!("{line}: {issues:?}"))?;
            assert_eq!(request.path, path, "{line}");
            assert_eq!(*request.value(), value, "{line}");
            assert!(!request.unvalidated, "{line}");
        }
        Ok(())
    }

    /// Invalid syntax and scalars cannot use a known context as a raw escape.
    #[test]
    fn invalid_context_leaves_are_refused() -> Result<(), Box<dyn Error>> {
        let catalog = Catalog::for_firmware_and_model("5.1.0".parse()?, Some("KN-1811"))?;
        for line in [
            "interface Bridge0 description",
            "interface Bridge0 up extra",
            "interface Bridge0 invented value",
            "interface Bridge0 security-level secret",
            "interface Bridge0 description a;reboot",
            "interface Bridge0 description a\nsystem reboot",
            "interface Bridge0 description $(reboot)",
            "interface Bridge0 description a&reboot",
            "interface bad$name up",
            "ip policy guest permit global bad$name",
            "ip dhcp pool guest range invalid 20",
            "ip dhcp pool guest range 192.0.2.10 invalid",
            "interface Wireguard0 wireguard listen-port invalid",
            "ip route 198.51.100.0 255.0.255.0 192.0.2.1",
        ] {
            let issues = catalog
                .validate_cli(line, RawAuthorization::default())
                .err()
                .ok_or_else(|| format!("accepted invalid line: {line}"))?;
            assert!(!issues.is_empty(), "{line}");
        }
        assert_eq!(
            catalog.validate_cli(
                "interface Wireguard0 wireguard listen-port invalid",
                RawAuthorization::default()
            ),
            Err(vec![ValidationIssue::InvalidValue {
                field: "port".to_owned()
            }])
        );
        Ok(())
    }

    /// CLI matching leaves secret classification and wire bytes with the existing owner.
    #[test]
    fn leaf_secret_slots_remain_protected() -> Result<(), Box<dyn Error>> {
        let catalog = Catalog::for_firmware_and_model("5.1.0".parse()?, Some("KN-1811"))?;
        let key = format!("{}=", "A".repeat(43));
        for (prefix, field) in [
            ("interface Wireguard0 wireguard private-key", "private-key"),
            ("user operator password md5", "hash"),
        ] {
            let request = catalog
                .validate_cli(&format!("{prefix} {key}"), RawAuthorization::default())
                .map_err(|issues| format!("{prefix}: {issues:?}"))?;
            assert_eq!(
                request
                    .protected_value()
                    .secret_pointers()
                    .collect::<Vec<_>>(),
                vec![format!("/{field}")]
            );
            assert!(
                !format!("{request:?}").contains(&key),
                "secret leaked in Debug"
            );
            let wire = request.protected_value().expose_for_send();
            assert!(
                wire.expose_secret()
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    == Some(key.as_str()),
                "secret bytes changed"
            );
        }
        Ok(())
    }
}
