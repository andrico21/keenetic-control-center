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
        planner::{Choices, MigrationMaps, MigrationPlan, PlanError, Planner},
        report::MigrationReport,
        source::SourceConfig,
    };
    use kcc_rci::{RouterUrl, auth::Credentials};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter,
        model::{Model, Profile},
    };
    use secrecy::SecretString;

    use super::*;

    /// Collects a real read-only inventory from the fake Ultra router.
    #[expect(
        clippy::missing_errors_doc,
        reason = "integration-test helper propagates fixture failures"
    )]
    async fn ultra_inventory() -> Result<TargetInventory, Box<dyn Error>> {
        let router = FakeRouter::builder(Profile::latest(Model::Kn1811)).build()?;
        let (address, handle) = router.serve(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let url = RouterUrl::from_str(&format!("http://{address}"))?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        );
        let client = InventoryClient::connect(url, credentials).await?;
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
            plan.phases.management[0].command,
            "interface Bridge0 ip address 198.51.100.1 255.255.255.0"
        );
        assert_eq!(plan.reconnect_url.as_deref(), Some("http://192.0.2.1"));
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
        let decoded: MigrationPlan = serde_json::from_str(&encoded)?;

        assert_eq!(decoded, plan);
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

        let json = report.to_json()?;
        let markdown = report.to_markdown();
        let html = report.to_html()?;

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
