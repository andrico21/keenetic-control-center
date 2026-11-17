//! Integration coverage for migration planning and redacted reports.

use alloc::collections::BTreeSet;
use core::{error::Error, net::SocketAddr, str::FromStr as _};

extern crate alloc;

#[cfg(test)]
mod tests {
    #![expect(
        clippy::indexing_slicing,
        reason = "integration-test fixtures assert exact plan phases and HTML tag stacks"
    )]
    #![expect(
        clippy::missing_panics_doc,
        reason = "integration-test fixtures assert exact plan phases and HTML tag stacks"
    )]
    #![expect(
        clippy::panic_in_result_fn,
        reason = "integration-test fixtures assert exact plan phases and HTML tag stacks"
    )]

    use kcc_config::config_text::flatten;
    use kcc_i18n::locale::Locale;
    use kcc_migrate::{
        inventory::{InventoryClient, TargetInventory, source_version},
        planner::{Choices, MigrationMaps, PlanError, Planner},
        report::MigrationReport,
        rules::Disposition,
        source::SourceConfig,
    };
    use kcc_rci::{RouterUrl, auth::Credentials};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, migration,
        model::{Model, Profile},
        outbound::loopback_client,
    };
    use secrecy::SecretString;

    use super::*;

    /// Collects a real read-only inventory from the fake Ultra router.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates fixture failures"
    )]
    async fn ultra_inventory() -> Result<TargetInventory, Box<dyn Error>> {
        managed_inventory(migration::Fixture::default()).await
    }

    /// Collects the fake Ultra's inventory with `scenario` applied.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates fixture failures"
    )]
    async fn managed_inventory(
        scenario: migration::Fixture,
    ) -> Result<TargetInventory, Box<dyn Error>> {
        let router = FakeRouter::builder(Profile::latest(Model::Kn1811))
            .build()?
            .with_migration(scenario);
        let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let url = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let client = InventoryClient::from_client(&loopback_client(url, credentials).await?);
        let inventory = TargetInventory::collect(&client, Some(source_version("5.1.0")?)).await?;
        handle.shutdown().await?;
        Ok(inventory)
    }

    /// Returns operator choices with the post-management URL confirmed.
    fn confirmed_choices() -> Choices {
        Choices::default().with_reconnect_url("http://192.0.2.1".to_owned())
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn giga_bridge_address_is_last_management_phase() -> Result<(), Box<dyn Error>> {
        let source = SourceConfig::from_bytes(
            concat!(
                "! $$$ Model: Keenetic Giga\n",
                "! $$$ Version: 5.1.0\n",
                "interface Bridge0\n",
                " ip address 198.51.100.1 255.255.255.0\n",
                "!\n",
            )
            .as_bytes(),
        )?;
        let target = ultra_inventory().await?;

        let plan = Planner::plan(
            &source,
            &target,
            &MigrationMaps::default(),
            &confirmed_choices(),
        )?;

        assert_eq!(plan.phases.management.len(), 1);
        assert_eq!(
            plan.phases.management[0].expose_command(),
            "interface Bridge0 ip address 198.51.100.1 255.255.255.0"
        );
        assert_eq!(plan.reconnect_url.as_deref(), Some("http://192.0.2.1"));
        Ok(())
    }

    /// G-06: with the management interface known, another bridge's address is an ordinary
    /// change; with it unknown, every bridge's address is a management change.
    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn only_the_management_bridge_address_is_a_management_change()
    -> Result<(), Box<dyn Error>> {
        let source = SourceConfig::from_bytes(
            b"interface Bridge5\n ip address 198.51.100.65 255.255.255.192\n!\n",
        )?;
        let mut scenario = migration::Fixture::default();
        scenario.interfaces = Some(serde_json::json!({
            "Bridge0": {"type": "Bridge", "link": "up", "address": "127.0.0.1"}
        }));
        let known = managed_inventory(scenario).await?;
        let unknown = ultra_inventory().await?;
        assert_eq!(known.management_interface.as_deref(), Some("Bridge0"));
        assert_eq!(unknown.management_interface, None);
        for (target, management) in [(&known, 0_usize), (&unknown, 1_usize)] {
            let plan = Planner::plan(
                &source,
                target,
                &MigrationMaps::default(),
                &confirmed_choices(),
            )?;
            assert_eq!(plan.phases.management.len(), management);
            assert_eq!(
                plan.phases.additive.len(),
                1_usize.saturating_sub(management)
            );
        }
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn already_present_target_lines_are_skipped() -> Result<(), Box<dyn Error>> {
        let target = ultra_inventory().await?;
        let existing = flatten(&target.running_config)
            .first()
            .map(ToString::to_string)
            .ok_or("target fixture has no running lines")?;
        let source = SourceConfig::from_bytes(existing.as_bytes())?;

        let plan = Planner::plan(
            &source,
            &target,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;

        assert_eq!(plan.phases.additive.len(), 0);
        assert_eq!(plan.phases.management.len(), 0);
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn plan_json_round_trips() -> Result<(), Box<dyn Error>> {
        let source = SourceConfig::from_bytes(b"system description migrated\n")?;
        let target = ultra_inventory().await?;
        let plan = Planner::plan(
            &source,
            &target,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;

        let encoded = serde_json::to_string(&plan)?;
        let decoded: serde_json::Value = serde_json::from_str(&encoded)?;

        assert_eq!(serde_json::to_value(&plan)?, decoded);
        assert_eq!(decoded["plan_id"], plan.plan_id);
        assert_eq!(
            decoded["source_fingerprint"],
            serde_json::to_value(&plan.source_fingerprint)?
        );
        assert_eq!(
            decoded["target_fingerprint"],
            serde_json::to_value(&plan.target_fingerprint)?
        );
        assert_eq!(decoded["phases"]["additive"][0]["command"], "<redacted>");
        assert_eq!(
            plan.phases.additive[0].expose_command(),
            "system description migrated"
        );
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn every_report_format_redacts_ns3_and_html_is_well_formed() -> Result<(), Box<dyn Error>>
    {
        let source = SourceConfig::from_bytes(
            b"interface Bridge9\n web-api password ns3 encoded-secret\n!\n",
        )?;
        let target = ultra_inventory().await?;
        let plan = Planner::plan(
            &source,
            &target,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;
        let report = MigrationReport::from_plan(&plan, Locale::En);

        assert_eq!(plan.phases.additive.len(), 0);
        assert_eq!(plan.items[0].disposition, Disposition::Unsupported);
        assert!(
            !format!("{plan:?}").contains("encoded-secret"),
            "plan Debug must not disclose executable secrets"
        );
        assert!(
            !serde_json::to_string(&plan)?.contains("encoded-secret"),
            "printable plan JSON must not disclose executable secrets"
        );

        let json = report.to_json()?;
        let markdown = report.to_markdown(Locale::En);
        let html = report.to_html(Locale::En)?;

        assert!(!json.contains("ns3 "));
        assert!(!markdown.contains("ns3 "));
        assert!(!html.contains("ns3 "));
        assert_html_closed(&html)?;
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn unresolved_needs_input_blocks_planning() -> Result<(), Box<dyn Error>> {
        let source = SourceConfig::from_bytes(
            concat!(
                "! $$$ Model: Keenetic Giga\n",
                "user admin password md5 source-hash\n",
            )
            .as_bytes(),
        )?;
        let target = ultra_inventory().await?;

        let result = Planner::plan(
            &source,
            &target,
            &MigrationMaps::default(),
            &Choices::default(),
        );

        assert!(matches!(
            result,
            Err(PlanError::PlanBlocked { items })
                if items.len() == 1 && items[0].needed_input.is_some()
        ));
        Ok(())
    }

    /// G-15: every report format carries the redacted command text of each item, and the
    /// secret of a secret-bearing line never reaches any of them.
    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn reports_carry_redacted_command_text() -> Result<(), Box<dyn Error>> {
        let secret = format!("plain-secret-{}", 4_711_u16);
        let source = SourceConfig::from_bytes(
            format!(
                "system description migrated\ninterface Bridge9\n web-api password {secret}\n!\n"
            )
            .as_bytes(),
        )?;
        let target = ultra_inventory().await?;
        let plan = Planner::plan(
            &source,
            &target,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;
        let report = MigrationReport::from_plan(&plan, Locale::En);
        let json = report.to_json()?;
        let markdown = report.to_markdown(Locale::En);
        let html = report.to_html(Locale::En)?;

        assert_eq!(report.items[0].before, "system description migrated");
        assert_eq!(
            report.items[0].after.as_deref(),
            Some("system description migrated")
        );
        assert!(json.contains("\"before\": \"system description migrated\""));
        assert!(markdown.contains("`system description migrated`"));
        assert!(html.contains("<code>system description migrated</code>"));
        assert!(
            report
                .items
                .iter()
                .any(|item| item.before == "interface Bridge9 web-api password <redacted>"),
            "{:?}",
            report.items
        );
        for rendered in [&json, &markdown, &html] {
            assert!(!rendered.contains(&secret), "secret leaked: {rendered}");
        }
        Ok(())
    }

    /// G-15: the report skeleton comes from the locale files; a Russian report has no
    /// English headings and declares its language.
    #[tokio::test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    async fn report_skeleton_is_localized() -> Result<(), Box<dyn Error>> {
        let source = SourceConfig::from_bytes(b"system description migrated\n")?;
        let target = ultra_inventory().await?;
        let plan = Planner::plan(
            &source,
            &target,
            &MigrationMaps::default(),
            &Choices::default(),
        )?;
        let report = MigrationReport::from_plan(&plan, Locale::Ru);
        let markdown = report.to_markdown(Locale::Ru);
        let html = report.to_html(Locale::Ru)?;
        for english in [
            "Migration report",
            "Counts",
            "Items",
            "Residual target settings",
        ] {
            assert!(!markdown.contains(english), "{english} in {markdown}");
            assert!(!html.contains(english), "{english} in {html}");
        }
        assert!(
            html.starts_with("<!doctype html><html lang=\"ru\">"),
            "{html}"
        );
        assert_html_closed(&html)?;
        Ok(())
    }

    /// Command text that looks like markup stays text in the HTML report and cannot leave
    /// its code span in the Markdown report.
    #[test]
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test assertions define the task contract"
    )]
    fn hostile_command_text_is_escaped() -> Result<(), Box<dyn Error>> {
        let hostile = "interface Bridge9 description \"<script>x</script> ``` [a](b)\"";
        let report: MigrationReport = serde_json::from_value(serde_json::json!({
            "schema_version": 1_u32,
            "plan_id": "plan",
            "counts": {"copy": 1_usize},
            "items": [{"source_index": 0_usize, "disposition": "copy", "before": hostile,
                "after": hostile, "reason": "<b>reason</b>"}],
            "target_not_clean": false,
            "residual": []
        }))?;
        let html = report.to_html(Locale::En)?;
        let markdown = report.to_markdown(Locale::En);
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&#60;script&#62;"), "{html}");
        assert_html_closed(&html)?;
        assert!(
            markdown.contains(&format!("```` {hostile} ````")),
            "{markdown}"
        );
        Ok(())
    }

    /// Checks nesting and closure for the small tag vocabulary emitted by the report template.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper reports malformed generated HTML"
    )]
    fn assert_html_closed(html: &str) -> Result<(), Box<dyn Error>> {
        let void = BTreeSet::from(["meta"]);
        let mut stack = Vec::new();
        for fragment in html.split('<').skip(1) {
            let Some(tag_text) = fragment.split_once('>').map(|(tag, _rest)| tag) else {
                return Err("unterminated HTML tag".into());
            };
            if tag_text.starts_with('!') {
                continue;
            }
            if let Some(closing) = tag_text.strip_prefix('/') {
                let name = closing.split_whitespace().next().unwrap_or_default();
                if stack.pop().as_deref() != Some(name) {
                    return Err(format!("misnested closing tag: {name}").into());
                }
            } else {
                let name = tag_text.split_whitespace().next().unwrap_or_default();
                if !void.contains(name) && !tag_text.ends_with('/') {
                    stack.push(name.to_owned());
                }
            }
        }
        if stack.is_empty() {
            Ok(())
        } else {
            Err(format!("unclosed HTML tags: {stack:?}").into())
        }
    }
}
