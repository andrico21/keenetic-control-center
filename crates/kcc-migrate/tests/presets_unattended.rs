//! Which reviewed preset plans may run without an operator.

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
        reason = "integration assertions establish the unattended preset contract"
    )]

    use alloc::sync::Arc;
    use core::error::Error;

    use kcc_app::audit::{Actor, ActorKind};
    use kcc_config::config_text::parse;
    use kcc_migrate::{
        apply::ApplyRequest,
        inventory::{InventoryClient, TargetInventory, source_version},
        planner::{Choices, MigrationMaps},
        presets::{
            apply::{PresetApplyOptions, PresetApplyRequest, request},
            groups::SettingsGroupEngine,
            model::{CaptureRequest, Preset, PresetSource, PresetSourceKind},
            plan::{PresetMode, PresetPlan, plan},
            unattended::{UnattendedRefusal, refusal},
        },
    };
    use kcc_testkit::{FaultInjection, model::Profile};
    use secrecy::SecretString;

    use crate::support::Fixture;

    /// A preset of `group` captured from `text`.
    fn captured(group: &str, text: &str) -> Result<Preset, Box<dyn Error>> {
        let source = parse(text)?;
        let selection = SettingsGroupEngine::embedded()?.select(&source, &[group])?;
        Ok(Preset::captured(
            CaptureRequest::new(
                "unattended".to_owned(),
                "Unattended".to_owned(),
                String::new(),
                vec![group.to_owned()],
                PresetSource::new(
                    PresetSourceKind::Router,
                    None,
                    "Keenetic Giga".to_owned(),
                    "4.3.0".to_owned(),
                    1_800_000_000,
                ),
                "tester".to_owned(),
            ),
            selection,
        ))
    }

    /// The target's inventory.
    async fn inventory(fixture: &Fixture) -> Result<TargetInventory, Box<dyn Error>> {
        let client = fixture
            .registry
            .bootstrap_client(&fixture.role, "target")
            .await?;
        Ok(TargetInventory::collect(
            &InventoryClient::from_client(&client),
            Some(source_version("4.3.0")?),
        )
        .await?)
    }

    /// The Merge plan of `preset` with `choices`, and its protected request with `options`.
    fn planned(
        fixture: &Fixture,
        (preset, inventory): (&Preset, &TargetInventory),
        choices: &Choices,
        options: PresetApplyOptions,
    ) -> Result<(PresetPlan, ApplyRequest), Box<dyn Error>> {
        let reviewed = plan(
            preset,
            inventory,
            PresetMode::Merge,
            &MigrationMaps::default(),
            choices,
        )?;
        let mut input = PresetApplyRequest::new(
            Arc::clone(&fixture.workflow),
            fixture.audit.clone(),
            Actor::new(ActorKind::System, "schedule:0000000000000e01".to_owned()),
            fixture.role.clone(),
            "target".to_owned(),
            preset.clone(),
            reviewed.clone(),
            inventory.clone(),
        );
        input.options = options;
        Ok((reviewed, request(input)?))
    }

    /// Todo 14: only a ready plan without management or WireGuard key lines runs unattended.
    ///
    /// A plan with a line that still needs input, one with a management-phase line and
    /// one that sets a WireGuard private key (copied or generated on the router) may not.
    #[tokio::test]
    async fn only_a_ready_plan_without_management_or_wireguard_key_lines_runs_unattended()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::spawn(Profile::default(), FaultInjection::default()).await?;
        let target = inventory(&fixture).await?;
        let defaults = PresetApplyOptions::default();

        let dns = captured("dns-secure", "dns-proxy tls upstream 1.1.1.1 853\n")?;
        let (ready, ordinary) = planned(&fixture, (&dns, &target), &Choices::default(), defaults)?;
        assert_eq!(refusal(&ready, &ordinary), None, "an ordinary ready plan");

        let hashed = captured("router-users", "user operator\n password md5 deadbeef\n")?;
        let mut typed = Choices::default();
        drop(typed.new_passwords.insert(
            "operator".to_owned(),
            SecretString::from(format!("typed-{}", 7_u8)),
        ));
        let (_resolved, resolved_request) =
            planned(&fixture, (&hashed, &target), &typed, defaults)?;
        let unresolved = plan(
            &hashed,
            &target,
            PresetMode::Merge,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;
        assert_eq!(
            refusal(&unresolved, &resolved_request),
            Some(UnattendedRefusal::NotReady)
        );

        let plain = format!("user operator\n password plain plain-{}\n", 7_u8);
        let management = captured("router-users", &plain)?;
        let (management_plan, management_request) = planned(
            &fixture,
            (&management, &target),
            &Choices::default(),
            defaults,
        )?;
        assert!(
            !management_request.plan.phases.management.is_empty(),
            "the fixture plans a management line"
        );
        assert_eq!(
            refusal(&management_plan, &management_request),
            Some(UnattendedRefusal::ManagementLines)
        );

        let key = format!("{}=", "A".repeat(43));
        let wireguard = captured(
            "vpn-clients",
            &format!("interface Wireguard9\n wireguard private-key {key}\n"),
        )?;
        for options in [defaults, defaults.keep_wireguard_keys()] {
            let (key_plan, key_request) = planned(
                &fixture,
                (&wireguard, &target),
                &Choices::default(),
                options,
            )?;
            assert_eq!(
                refusal(&key_plan, &key_request),
                Some(UnattendedRefusal::WireGuardKey),
                "{options:?}"
            );
        }
        fixture.handle.shutdown().await?;
        Ok(())
    }
}
