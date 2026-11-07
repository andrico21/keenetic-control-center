//! Integration coverage for preset settings-group selection.

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration-test assertions define the settings-group contract"
    )]

    use core::{error::Error, str::FromStr as _};
    use std::fs;

    use kcc_app::{
        permissions::{Permission, Role},
        persist::StateStore,
        secrets::MasterKey,
    };
    use kcc_catalog::Catalog;
    use kcc_config::config_text::parse;
    use kcc_migrate::presets::{
        groups::SettingsGroupEngine,
        model::{CaptureRequest, PresetSource, PresetSourceKind},
        store::{PresetError, PresetStore},
    };
    use kcc_rci::version::FirmwareVersion;
    use tempfile::TempDir;

    #[test]
    fn embedded_groups_cover_required_inventory_and_catalogs() -> Result<(), Box<dyn Error>> {
        let engine = SettingsGroupEngine::embedded()?;
        let groups = engine.groups()?;
        let ids = groups
            .iter()
            .map(|group| group.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "dns-secure",
                "dns-records-routing",
                "policies",
                "static-routes",
                "firewall",
                "vpn-clients",
                "wifi",
                "system-baseline",
                "router-users",
                "schedules",
            ]
        );

        let versions = ["4.3.9", "5.0.12", "5.1.1"]
            .into_iter()
            .map(FirmwareVersion::from_str)
            .collect::<Result<Vec<_>, _>>()?;
        let catalogs = versions
            .into_iter()
            .map(|version| Catalog::for_firmware_and_model(version, None))
            .collect::<Result<Vec<_>, _>>()?;
        for group in groups {
            for pattern in &group.include {
                assert!(
                    catalogs
                        .iter()
                        .any(|catalog| catalog.commands().any(|command| {
                            SettingsGroupEngine::pattern_matches_catalog(pattern, &command.path)
                        })),
                    "{} pattern did not match a generated catalog command: {pattern}",
                    group.id
                );
            }
        }
        Ok(())
    }

    #[test]
    fn selected_group_includes_only_owned_source_lines() -> Result<(), Box<dyn Error>> {
        let source =
            parse("dns-proxy\n tls\n  upstream dot.example 853\nip host example.test 192.0.2.1\n")?;

        let selection = SettingsGroupEngine::embedded()?.select(&source, &["dns-secure"])?;

        assert_eq!(selection.groups, ["dns-secure"]);
        assert_eq!(
            selection
                .lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["dns-proxy tls upstream dot.example 853"]
        );
        Ok(())
    }

    #[test]
    fn wifi_selection_auto_includes_referenced_schedule() -> Result<(), Box<dyn Error>> {
        let source = parse(
            "schedule WorkHours\n description office\nschedule GuestHours\n description guest\ninterface WifiMaster0/AccessPoint0\n ssid Office\n schedule WorkHours\n",
        )?;

        let selection = SettingsGroupEngine::embedded()?.select(&source, &["wifi"])?;

        assert_eq!(selection.groups, ["wifi"]);
        assert_eq!(
            selection
                .lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "schedule WorkHours description office",
                "interface WifiMaster0/AccessPoint0 ssid Office",
                "interface WifiMaster0/AccessPoint0 schedule WorkHours",
            ]
        );
        Ok(())
    }

    #[test]
    fn dns_routing_selection_includes_referenced_policy_and_object_group()
    -> Result<(), Box<dyn Error>> {
        let source = parse(
            "object-group fqdn Allowed\n include example.test\nobject-group fqdn Unused\n include unused.test\nip policy Policy0\n permit\nip policy OtherPolicy\n permit\ndns-proxy route Allowed Policy0\n",
        )?;

        let selection =
            SettingsGroupEngine::embedded()?.select(&source, &["dns-records-routing"])?;

        assert_eq!(selection.groups, ["dns-records-routing"]);
        assert_eq!(
            selection
                .lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "object-group fqdn Allowed include example.test",
                "object-group fqdn Unused include unused.test",
                "ip policy Policy0 permit",
                "dns-proxy route Allowed Policy0",
            ]
        );
        Ok(())
    }

    #[test]
    fn saved_preset_is_encrypted_and_revealed_only_with_permission() -> Result<(), Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let store = PresetStore::new(
            StateStore::open(temporary.path())?,
            MasterKey::from_bytes([7_u8; 32]),
        );
        let payload = "QUFB".repeat(6);
        let source = parse(&format!("user operator\n password md5 ns3 {payload}\n"))?;
        let operator = role("operator", [Permission::Read, Permission::Migrate], "lab-*");
        let administrator = role(
            "admin",
            [
                Permission::Read,
                Permission::Migrate,
                Permission::RevealSecrets,
            ],
            "lab-*",
        );

        let captured = store.capture(
            &operator,
            &source,
            request("encrypted", "lab-one", "router-users"),
        )?;

        assert!(
            !captured
                .lines
                .iter()
                .any(|line| line.to_string().contains("QUFB"))
        );
        let bytes = fs::read(temporary.path().join("presets/encrypted.json"))?;
        assert!(!bytes.windows(4).any(|window| window == b"ns3 "));
        assert!(!bytes.windows(4).any(|window| window == b"QUFB"));
        assert!(
            store
                .get(&operator, "encrypted")?
                .lines
                .iter()
                .all(|line| !line.to_string().contains("QUFB"))
        );
        assert!(
            store
                .get(&administrator, "encrypted")?
                .lines
                .iter()
                .any(|line| line.to_string().contains("QUFB"))
        );
        Ok(())
    }

    #[test]
    fn source_scope_hides_and_refuses_saved_presets() -> Result<(), Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let store = PresetStore::new(
            StateStore::open(temporary.path())?,
            MasterKey::from_bytes([9_u8; 32]),
        );
        let source = parse("ip host example.test 192.0.2.1\n")?;
        let administrator = role("admin", [Permission::Read, Permission::Migrate], "*");
        let lab_operator = role("operator", [Permission::Read, Permission::Migrate], "lab-*");
        let _captured = store.capture(
            &administrator,
            &source,
            request("production", "prod-1", "dns-records-routing"),
        )?;

        assert!(store.list(&lab_operator)?.is_empty());
        assert!(matches!(
            store.get(&lab_operator, "production"),
            Err(PresetError::Forbidden)
        ));
        assert!(matches!(
            store.delete(&lab_operator, "production"),
            Err(PresetError::Forbidden)
        ));
        assert_eq!(store.get(&administrator, "production")?.id, "production");
        Ok(())
    }

    #[test]
    fn viewer_cannot_capture_preset() -> Result<(), Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let store = PresetStore::new(
            StateStore::open(temporary.path())?,
            MasterKey::from_bytes([11_u8; 32]),
        );
        let viewer = role("viewer", [Permission::Read], "*");

        let result = store.capture(
            &viewer,
            &parse("ip host example.test 192.0.2.1\n")?,
            request("blocked", "lab-one", "dns-records-routing"),
        );

        assert!(matches!(result, Err(PresetError::Forbidden)));
        assert!(!temporary.path().join("presets/blocked.json").exists());
        Ok(())
    }

    #[test]
    fn viewer_cannot_delete_preset() -> Result<(), Box<dyn Error>> {
        let temporary = TempDir::new()?;
        let store = PresetStore::new(
            StateStore::open(temporary.path())?,
            MasterKey::from_bytes([13_u8; 32]),
        );
        let administrator = role("admin", Permission::ALL, "*");
        let viewer = role("viewer", [Permission::Read], "*");
        let _captured = store.capture(
            &administrator,
            &parse("ip host example.test 192.0.2.1\n")?,
            request("viewer-blocked", "lab-one", "dns-records-routing"),
        )?;

        assert!(matches!(
            store.delete(&viewer, "viewer-blocked"),
            Err(PresetError::Forbidden)
        ));
        assert_eq!(
            store.get(&administrator, "viewer-blocked")?.id,
            "viewer-blocked"
        );
        Ok(())
    }

    fn role<const N: usize>(name: &str, permissions: [Permission; N], scope: &str) -> Role {
        Role::new(name.to_owned(), permissions, vec![scope.to_owned()])
    }

    fn request(id: &str, router: &str, group: &str) -> CaptureRequest {
        CaptureRequest::new(
            id.to_owned(),
            "Preset".to_owned(),
            String::new(),
            vec![group.to_owned()],
            PresetSource::new(
                PresetSourceKind::Router,
                Some(router.to_owned()),
                "KN-1811".to_owned(),
                "5.1.1".to_owned(),
                1_800_000_000,
            ),
            "tester".to_owned(),
        )
    }
}
