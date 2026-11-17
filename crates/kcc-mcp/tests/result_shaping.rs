//! Result shaping over a real session: field projection, page limits, and the input
//! schemas of the write tools.
extern crate alloc;

#[expect(
    dead_code,
    reason = "the shared MCP session support; this suite needs part of it"
)]
#[path = "support/lab.rs"]
mod lab;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the result shaping contract"
)]
mod tests {
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::{Value, json};

    use super::lab::{Lab, TestResult, admin};

    /// Two routers, `lab-1` and `lab-2`, behind an administrator session.
    async fn start() -> TestResult<Lab> {
        let routers = vec![
            ("lab-1", FakeRouter::builder(Profile::default()).build()?),
            ("lab-2", FakeRouter::builder(Profile::default()).build()?),
        ];
        Lab::start(routers, admin()).await
    }

    /// The input schema the session lists for `tool`.
    async fn tool_schema(lab: &Lab, tool: &str) -> TestResult<Value> {
        let listed = lab.client.list_all_tools().await?;
        let found = listed
            .into_iter()
            .find(|candidate| candidate.name == tool)
            .ok_or_else(|| format!("no tool {tool}"))?;
        Ok(Value::Object((*found.input_schema).clone()))
    }

    /// E-12: a `fields` projection keeps only the requested members of every list item,
    /// an unknown name is absent, and no projection leaves the items whole.
    #[tokio::test]
    async fn fields_projection_selects_item_members() -> TestResult {
        let lab = start().await?;
        let whole = lab.call("kcc_routers_list", json!({}), false).await?;
        let first = whole
            .value()?
            .pointer("/routers/0")
            .ok_or("no first router")?;
        assert!(first.get("tags").is_some(), "unprojected: {first}");
        let projected = lab
            .call(
                "kcc_routers_list",
                json!({"fields":["id","no_such_member"]}),
                false,
            )
            .await?;
        let routers = projected
            .value()?
            .get("routers")
            .and_then(Value::as_array)
            .ok_or("no routers")?;
        assert_eq!(routers.len(), 2);
        for router in routers {
            let keys = router.as_object().ok_or("item object")?;
            assert_eq!(keys.keys().collect::<Vec<_>>(), ["id"], "{router}");
        }
        lab.stop().await
    }

    /// E-20: a zero page limit is raised to one item and the next cursor of a page that has
    /// more items moves forward.
    #[tokio::test]
    async fn zero_limit_still_returns_one_item_and_a_moving_cursor() -> TestResult {
        let lab = start().await?;
        let listed = lab
            .call("kcc_routers_list", json!({"limit":0_u16}), false)
            .await?;
        let routers = listed.value()?.get("routers").and_then(Value::as_array);
        assert_eq!(routers.map(Vec::len), Some(1), "{listed:?}");
        let searched = lab
            .call(
                "kcc_catalog_search",
                json!({"host":"lab-1","query":"interface","limit":0_u16}),
                false,
            )
            .await?;
        let value = searched.value()?;
        let results = value.get("results").and_then(Value::as_array);
        assert_eq!(results.map(Vec::len), Some(1), "{value}");
        assert_eq!(value.get("next_cursor"), Some(&json!("1")), "{value}");
        lab.stop().await
    }

    /// E-18: `confirm` is described as required for management changes on every curated
    /// write tool, and the firewall tool lists no `index` or `description` input.
    #[tokio::test]
    async fn write_schemas_describe_confirm_and_drop_dead_inputs() -> TestResult {
        let lab = start().await?;
        for tool in [
            "kcc_routing_write",
            "kcc_policies_write",
            "kcc_nat_write",
            "kcc_firewall_write",
            "kcc_clients_write",
            "kcc_dhcp_write",
            "kcc_segments_write",
            "kcc_dns_write",
        ] {
            let schema = tool_schema(&lab, tool).await?;
            let confirm = schema
                .pointer("/properties/confirm/description")
                .and_then(Value::as_str)
                .ok_or("confirm description")?;
            assert!(
                confirm.contains("required when the change touches management"),
                "{tool}: {confirm}"
            );
        }
        let firewall = tool_schema(&lab, "kcc_firewall_write").await?;
        for dead in ["index", "description"] {
            assert!(
                firewall.pointer(&format!("/properties/{dead}")).is_none(),
                "{dead} is not an input of kcc_firewall_write"
            );
        }
        lab.stop().await
    }
}
