//! Step 3 with a numeric switch-port context.
//!
//! `segments create --port 1` writes `interface 1 switchport trunk vlan 5`: the step
//! continues with its own defaults and plans as the CLI and MCP do, while typed interface
//! names stay checked.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::fmt::Write as _;

    use axum::{http::StatusCode, response::Response};
    use kcc_config::config_text::flatten;
    use kcc_i18n::{bundle::tr, keys, locale::Locale};
    use kcc_migrate::{
        inventory::{InventoryClient, TargetInventory},
        planner::{Choices, MigrationMaps, MigrationPlan, Planner},
        source::SourceConfig,
    };
    use serde_json::Value;

    use crate::{
        flow::{form_values, moved},
        start,
        support::{Browser, Fixture, TestResult, text},
    };

    /// The switch-port line of the segment.
    const PORT_LINE: &str = "interface 1 switchport trunk vlan 5";

    /// The segment's lines (RFC 5737 addresses), the switch port among them.
    fn segment() -> [String; 4] {
        let address = format!("{}.0.113.65", 203_u8);
        [
            "interface Vlan5 vlan-id 5".to_owned(),
            PORT_LINE.to_owned(),
            format!("interface Bridge5 ip address {address} 255.255.255.192"),
            "interface Bridge5 include Vlan5".to_owned(),
        ]
    }

    /// The segment as an uploaded startup-config of a 4.3 Giga.
    fn segment_file() -> TestResult<String> {
        let mut text = "! $$$ Model: Keenetic Giga\n! $$$ Version: 4.3.0\n".to_owned();
        for line in segment() {
            let (context, setting) = line
                .split_once(' ')
                .and_then(|(_, rest)| rest.split_once(' '))
                .unwrap_or_default();
            writeln!(text, "interface {context}\n {setting}\n!")?;
        }
        Ok(text)
    }

    /// The source of a case: the router `giga` holding the segment, or the file.
    enum Source {
        /// `giga`, to `ultra` (KN-1811, current firmware).
        Router,
        /// The uploaded file, to `legacy` (KN-1811 on 4.3, documentation tier).
        File(String),
    }

    /// Steps 1 and 2 for `source`; returns the migration's page at the maps.
    async fn to_mapping(
        fixture: &Fixture,
        browser: &Browser,
        source: &Source,
    ) -> TestResult<String> {
        let page = start(fixture, browser).await?;
        let path = format!("{page}/source");
        let (read, target) = match source {
            Source::Router => {
                let fields = [("kind", "router"), ("router", "giga")];
                (
                    fixture.post_source(&path, browser, &fields, None).await?,
                    "ultra",
                )
            }
            Source::File(file) => {
                let fields = [("kind", "file")];
                let read = fixture
                    .post_source(&path, browser, &fields, Some(file))
                    .await?;
                (read, "legacy")
            }
        };
        moved(&read, &page)?;
        let chosen = [("router", target)];
        moved(
            &fixture
                .post(&format!("{page}/target"), browser, &chosen)
                .await?,
            &page,
        )?;
        let acknowledged = [("acknowledge", "yes")];
        let next = format!("{page}/target/continue");
        moved(&fixture.post(&next, browser, &acknowledged).await?, &page)?;
        Ok(page)
    }

    /// Posts the maps step with its rendered values, `changes` applied.
    async fn submit(
        fixture: &Fixture,
        browser: &Browser,
        page: &str,
        changes: &[(&str, &str)],
    ) -> TestResult<Response> {
        let form = text(fixture.get(page, browser).await?).await?;
        let fields = form_values(&form)
            .into_iter()
            .map(|(name, rendered)| {
                let typed = changes
                    .iter()
                    .find(|(from, _)| name.starts_with("interface-") && *from == rendered);
                let sent = typed.map_or(rendered, |(_, to)| (*to).to_owned());
                (name, sent)
            })
            .collect::<Vec<_>>();
        let pairs = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        fixture
            .post(&format!("{page}/mapping"), browser, &pairs)
            .await
    }

    /// Each plan item as `(line, disposition, reason)`.
    fn dispositions(plan: &Value) -> Vec<(Value, Value, Value)> {
        plan["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        let field = |name: &str| item[name].clone();
                        (
                            field("source_index"),
                            field("disposition"),
                            field("reason_key"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The plan `migrate plan` and `kcc_migration_plan` make (no maps, the source as
    /// read, the target's inventory), and the index of [`PORT_LINE`] in its items.
    async fn cli_plan(fixture: &Fixture, source: &Source) -> TestResult<(MigrationPlan, usize)> {
        let (mut config, target) = match source {
            Source::Router => {
                let text = fixture.handle("giga")?.startup_config_text();
                (SourceConfig::from_bytes(text.as_bytes())?, "ultra")
            }
            Source::File(file) => (SourceConfig::from_bytes(file.as_bytes())?, "legacy"),
        };
        if matches!(source, Source::Router) {
            let giga = fixture.registry().client("giga").await?;
            config.firmware = giga.detect().await?.firmware.or(config.firmware);
        }
        let client = fixture.registry().client(target).await?;
        let inventory =
            TargetInventory::collect(&InventoryClient::from_client(&client), config.firmware)
                .await?;
        let mut choices = Choices::default();
        choices.ack_documentation_tier = true;
        choices.reconnect_url = Some(format!("http://{}.0.2.1", 192_u8));
        let port = flatten(&config.ast)
            .iter()
            .position(|line| line.to_string() == PORT_LINE)
            .ok_or("the source holds the switch port")?;
        let plan = Planner::plan(&config, &inventory, &MigrationMaps::default(), &choices)?;
        Ok((plan, port))
    }

    /// The plan the wizard would build now.
    async fn web_plan(fixture: &Fixture, browser: &Browser, page: &str) -> TestResult<Value> {
        let response = fixture
            .get(&format!("{page}/download/plan.json"), browser)
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "plan.json");
        Ok(serde_json::from_str(&text(response).await?)?)
    }

    /// Gives `giga` the segment, saved to its startup configuration.
    async fn seed(fixture: &Fixture) -> TestResult {
        let client = fixture.registry().client("giga").await?;
        for line in segment() {
            drop(client.parse(&line).await?);
        }
        drop(client.parse("system configuration save").await?);
        Ok(())
    }

    #[tokio::test]
    async fn the_switch_port_defaults_continue_and_plan_as_the_cli_and_mcp() -> TestResult {
        let fixture = Fixture::new().await?;
        seed(&fixture).await?;
        let admin = fixture.login("admin").await?;
        for source in [Source::Router, Source::File(segment_file()?)] {
            let page = to_mapping(&fixture, &admin, &source).await?;
            let form = text(fixture.get(&page, &admin).await?).await?;
            assert!(
                form.contains(">1</th>") && !form.contains("type=\"text\" value=\"1\""),
                "the switch port is a port row, not a typed name: {form}"
            );
            let continued = submit(&fixture, &admin, &page, &[]).await?;
            moved(&continued, &page)?;
            let (cli, index) = cli_plan(&fixture, &source).await?;
            assert!(
                cli.items.iter().any(|item| item.source_index == index),
                "the CLI plans {PORT_LINE}"
            );
            let web = web_plan(&fixture, &admin, &page).await?;
            let planned = serde_json::to_value(&cli)?;
            assert_eq!(
                dispositions(&web),
                dispositions(&planned),
                "the same dispositions"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn typed_interface_names_stay_checked_in_every_locale() -> TestResult {
        let fixture = Fixture::new().await?;
        seed(&fixture).await?;
        for (account, locale) in [
            ("admin", Locale::En),
            ("without-save", Locale::Ru),
            ("without-write-save", Locale::Kk),
        ] {
            let browser = fixture.login(account).await?;
            let page = to_mapping(&fixture, &browser, &Source::Router).await?;
            let refused = submit(&fixture, &browser, &page, &[("Vlan5", "1")]).await?;
            assert_eq!(
                refused.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{account}"
            );
            let body = text(refused).await?;
            let mut args = fluent_bundle::FluentArgs::new();
            args.set("name", "1");
            let message = tr(locale, keys::WEB_MIGRATE_MAP_ERROR_NAME, Some(&args));
            let escaped = message.replace('\'', "&#39;").replace('"', "&#34;");
            assert!(body.contains(&escaped), "{account}: {message} in {body}");
            assert!(
                !body.contains("web-migrate-"),
                "{account}: a raw key in {body}"
            );
            let renamed = submit(&fixture, &browser, &page, &[("Vlan5", "Vlan7")]).await?;
            moved(&renamed, &page)?;
            let review = text(fixture.get(&page, &browser).await?).await?;
            // The rename reaches the classification: the membership line is remapped. (The
            // `vlan-id` line itself is unsupported on this target, as in the CLI plan.)
            assert!(
                review.contains("interface Bridge5 include Vlan7"),
                "{account}: {review}"
            );
        }
        Ok(())
    }
}
