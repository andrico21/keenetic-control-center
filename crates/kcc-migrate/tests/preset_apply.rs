//! Preset application acceptance through the protected migration applier.

extern crate alloc;

#[path = "support/apply_fixture.rs"]
#[expect(
    dead_code,
    reason = "the shared apply fixture exposes migration helpers not needed by this sibling suite"
)]
mod support;

#[cfg(test)]
mod tests {
    #![expect(
        clippy::missing_errors_doc,
        clippy::missing_panics_doc,
        clippy::panic_in_result_fn,
        reason = "integration assertions establish preset apply and authorization contracts"
    )]

    use alloc::sync::Arc;
    use core::error::Error;

    use kcc_app::{
        audit::{Actor, ActorKind},
        permissions::{Permission, Role},
    };
    use kcc_config::config_text::{flatten, parse};
    use kcc_i18n::locale::Locale;
    use kcc_migrate::{
        apply::{Applier, ApplyError, ApplyWarning},
        inventory::{InventoryClient, TargetInventory, source_version},
        planner::{Choices, MigrationMaps},
        presets::{
            apply::{PresetApplyError, PresetApplyOptions, PresetApplyRequest, request},
            groups::SettingsGroupEngine,
            model::{CaptureRequest, Preset, PresetSource, PresetSourceKind},
            plan::{PresetMode, PresetPlanError, plan},
        },
        report::MigrationReport,
    };
    use kcc_testkit::{
        FaultInjection,
        model::{Firmware, Model, Profile},
    };

    use crate::support::Fixture;

    #[tokio::test]
    async fn dns_secure_merge_applies_only_captured_lines() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let preset = captured(
            "dns-secure",
            "dns-proxy tls upstream 1.1.1.1 853\ndns-proxy tls upstream 9.9.9.9 853\n",
            None,
        )?;
        let before = fixture.handle.running_config_text();
        let input = apply_input(&fixture, preset, PresetMode::Merge).await?;

        let (_id, done) = Applier::start(&fixture.runner, request(input)?).await?;
        let mut applier = done.await??;

        assert_eq!(applier.report().failure, None);
        let after = configured_lines(&fixture.handle.running_config_text())?;
        assert!(after.contains(&"dns-proxy tls upstream 1.1.1.1 853".to_owned()));
        assert!(after.contains(&"dns-proxy tls upstream 9.9.9.9 853".to_owned()));
        assert_eq!(
            after.len(),
            configured_lines(&before)?.len().saturating_add(2)
        );
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn dns_secure_mirror_removes_target_only_upstream() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        drop(
            fixture
                .registry
                .client("target")
                .await?
                .parse("dns-proxy tls upstream 8.8.8.8 853")
                .await?,
        );
        let preset = captured("dns-secure", "dns-proxy tls upstream 1.1.1.1 853\n", None)?;
        let input = apply_input(&fixture, preset, PresetMode::Mirror).await?;

        let (_id, done) = Applier::start(&fixture.runner, request(input)?).await?;
        let mut applier = done.await??;

        let lines = configured_lines(&fixture.handle.running_config_text())?;
        assert!(!lines.contains(&"dns-proxy tls upstream 8.8.8.8 853".to_owned()));
        assert!(lines.contains(&"dns-proxy tls upstream 1.1.1.1 853".to_owned()));
        applier.rollback().await?;
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn wireguard_regenerates_by_default_and_can_keep_with_warning()
    -> Result<(), Box<dyn Error>> {
        for regenerate in [true, false] {
            let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
            let private = format!("{}=", "A".repeat(43));
            let preset = captured(
                "vpn-clients",
                &format!("interface Wireguard9\n wireguard private-key {private}\n"),
                None,
            )?;
            let mut input = apply_input(&fixture, preset, PresetMode::Merge).await?;
            input.options = if regenerate {
                PresetApplyOptions::default()
            } else {
                PresetApplyOptions::default().keep_wireguard_keys()
            };

            let (_id, done) = Applier::start(&fixture.runner, request(input)?).await?;
            let mut applier = done.await??;

            if regenerate {
                assert_eq!(applier.report().wireguard_public_keys.len(), 1);
                assert_eq!(applier.report().warnings, []);
            } else {
                assert_eq!(applier.report().wireguard_public_keys, []);
                assert_eq!(
                    applier.report().warnings,
                    [ApplyWarning::WireGuardPrivateKeyKept {
                        interface: "Wireguard9".to_owned()
                    }]
                );
            }
            assert!(!fixture.handle.running_config_text().contains(&private));
            applier.rollback().await?;
            drop(applier);
            fixture.handle.shutdown().await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn source_or_target_scope_refusal_makes_zero_router_requests()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let preset = captured(
            "dns-secure",
            "dns-proxy tls upstream 1.1.1.1 853\n",
            Some("prod-source"),
        )?;
        let mut input = apply_input(&fixture, preset, PresetMode::Merge).await?;
        input.role = Role::new(
            "operator".to_owned(),
            [Permission::Read, Permission::Migrate],
            vec!["lab-*".to_owned()],
        );
        input.target = "prod-1".to_owned();
        let before = fixture.handle.request_count();

        assert!(matches!(request(input), Err(PresetApplyError::Forbidden)));
        assert_eq!(fixture.handle.request_count(), before);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn viewer_apply_refusal_makes_zero_router_requests() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let preset = captured("dns-secure", "dns-proxy tls upstream 1.1.1.1 853\n", None)?;
        let mut input = apply_input(&fixture, preset, PresetMode::Merge).await?;
        input.role = Role::new(
            "viewer".to_owned(),
            [Permission::Read],
            vec!["*".to_owned()],
        );
        let before = fixture.handle.request_count();

        assert!(matches!(request(input), Err(PresetApplyError::Forbidden)));
        assert_eq!(fixture.handle.request_count(), before);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn newer_preset_is_refused_by_older_target_before_apply() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(
            Profile::new(Model::Kn1811, Firmware::V4_3)?,
            FaultInjection::default(),
        )
        .await?;
        let mut preset = captured("dns-secure", "dns-proxy tls upstream 1.1.1.1 853\n", None)?;
        preset.source.firmware_version = "5.1.1".to_owned();
        let client = fixture
            .registry
            .bootstrap_client(&fixture.role, "target")
            .await?;
        let inventory_client = InventoryClient::from_client(&client);
        let inventory =
            TargetInventory::collect(&inventory_client, Some(source_version("4.3.0")?)).await?;
        let before = fixture.handle.request_count();

        assert!(matches!(
            plan(
                &preset,
                &inventory,
                PresetMode::Merge,
                &MigrationMaps::default(),
                &Choices::default()
            ),
            Err(PresetPlanError::TargetFirmwareOlder)
        ));
        assert_eq!(fixture.handle.request_count(), before);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn injected_line_failure_rolls_back_original_startup_identity()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(
            Profile::default(),
            FaultInjection::default().fail_parse_matching("dns-proxy tls upstream 9.9.9.9", 1),
        )
        .await?;
        let before = fixture.handle.startup_config_text();
        let preset = captured(
            "dns-secure",
            "dns-proxy tls upstream 1.1.1.1 853\ndns-proxy tls upstream 9.9.9.9 853\n",
            None,
        )?;
        let input = apply_input(&fixture, preset, PresetMode::Merge).await?;

        let (_id, done) = Applier::start(&fixture.runner, request(input)?).await?;
        let mut applier = done.await??;

        assert_eq!(applier.report().failure, Some(ApplyError::Stopped));
        applier.rollback().await?;
        assert_eq!(fixture.handle.startup_config_text(), before);
        drop(applier);
        fixture.handle.shutdown().await?;
        Ok(())
    }

    /// G-15: a preset plan's report lists its items with redacted command text and never
    /// the captured key.
    #[tokio::test]
    async fn preset_report_lists_redacted_items() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let private = format!("{}=", "B".repeat(43));
        let preset = captured(
            "vpn-clients",
            &format!("interface Wireguard9\n wireguard private-key {private}\n"),
            None,
        )?;
        let input = apply_input(&fixture, preset, PresetMode::Merge).await?;
        let reviewed = request(input)?;
        let report = MigrationReport::from_plan(&reviewed.plan, Locale::En);
        let json = report.to_json()?;
        assert!(
            report
                .items
                .iter()
                .any(|item| item.before == "interface Wireguard9 wireguard private-key <redacted>"),
            "{json}"
        );
        assert!(!json.contains(&private));
        fixture.handle.shutdown().await?;
        Ok(())
    }

    async fn apply_input(
        fixture: &Fixture,
        preset: Preset,
        mode: PresetMode,
    ) -> Result<PresetApplyRequest, Box<dyn Error>> {
        let client = fixture
            .registry
            .bootstrap_client(&fixture.role, "target")
            .await?;
        let inventory_client = InventoryClient::from_client(&client);
        let inventory = TargetInventory::collect(
            &inventory_client,
            Some(source_version(&preset.source.firmware_version)?),
        )
        .await?;
        let reviewed = plan(
            &preset,
            &inventory,
            mode,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;
        Ok(PresetApplyRequest::new(
            Arc::clone(&fixture.workflow),
            fixture.audit.clone(),
            Actor::new(ActorKind::Cli, "operator".to_owned()),
            fixture.role.clone(),
            "target".to_owned(),
            preset,
            reviewed,
            inventory,
        ))
    }

    fn captured(group: &str, text: &str, router: Option<&str>) -> Result<Preset, Box<dyn Error>> {
        let source = parse(text)?;
        let selection = SettingsGroupEngine::embedded()?.select(&source, &[group])?;
        Ok(Preset::captured(
            CaptureRequest::new(
                "transient".to_owned(),
                "Transient".to_owned(),
                String::new(),
                vec![group.to_owned()],
                PresetSource::new(
                    PresetSourceKind::Router,
                    router.map(str::to_owned),
                    "Keenetic Giga".to_owned(),
                    "4.3.0".to_owned(),
                    1_800_000_000,
                ),
                "tester".to_owned(),
            ),
            selection,
        ))
    }

    fn configured_lines(text: &str) -> Result<Vec<String>, Box<dyn Error>> {
        Ok(flatten(&parse(text)?)
            .iter()
            .map(ToString::to_string)
            .collect())
    }
}
