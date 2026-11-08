//! MCP resources honour the identity's router scope and expose catalog entries.
extern crate alloc;

#[path = "support/lab.rs"]
#[expect(
    dead_code,
    reason = "resource tests use the session and request counters, not the tool-call helpers"
)]
mod lab;
#[path = "support/resources.rs"]
mod resources;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance assertions establish the MCP resource contract"
)]
mod tests {
    use kcc_testkit::{FakeRouter, model::Profile};
    use serde_json::Value;

    use super::{
        lab::{Lab, TestResult, lab_only},
        resources::{read, uris},
    };

    /// Snapshot URI of router `id`.
    fn snapshot(id: &str) -> String {
        format!("kcc://router/{id}/snapshot")
    }

    /// A session scoped to `lab-*` next to registered `lab-1` and `prod-1` routers.
    async fn scoped_lab() -> TestResult<Lab> {
        Lab::start(
            vec![
                ("lab-1", FakeRouter::builder(Profile::default()).build()?),
                ("prod-1", FakeRouter::builder(Profile::default()).build()?),
            ],
            lab_only(),
        )
        .await
    }

    /// `resources/list` shows `lab-1` and hides `prod-1`.
    #[tokio::test]
    async fn list_shows_only_routers_in_scope() -> TestResult {
        let lab = scoped_lab().await?;

        let listed = uris(&lab).await?;

        assert_eq!(listed, vec![snapshot("lab-1")]);
        lab.stop().await
    }

    /// Reading `prod-1` is forbidden and never reaches it; `lab-1` returns its snapshot.
    #[tokio::test]
    async fn read_is_forbidden_outside_scope_and_never_contacts_the_router() -> TestResult {
        let lab = scoped_lab().await?;
        let prod_before = lab.requests("prod-1")?;
        let lab_before = lab.requests("lab-1")?;

        let forbidden = read(&lab, &snapshot("prod-1")).await?;
        let allowed = read(&lab, &snapshot("lab-1")).await?;

        assert_eq!(forbidden, Err("forbidden".to_owned()));
        assert_eq!(lab.requests("prod-1")?, prod_before, "prod-1 was contacted");
        let value = allowed.map_err(|code| format!("lab-1 read failed: {code}"))?;
        assert_eq!(value.get("host").and_then(Value::as_str), Some("lab-1"));
        assert!(
            value.get("system").is_some_and(Value::is_object),
            "snapshot has system data: {value}"
        );
        assert!(lab.requests("lab-1")? > lab_before, "lab-1 was polled");
        lab.stop().await
    }

    /// A catalog URI resolves to the command's kind, `no` support and schema.
    #[tokio::test]
    async fn catalog_resource_describes_a_command() -> TestResult {
        let lab = scoped_lab().await?;

        let value = read(&lab, "kcc://catalog/5.1/ip%20arp")
            .await?
            .map_err(|code| format!("catalog read failed: {code}"))?;

        assert_eq!(value.get("path").and_then(Value::as_str), Some("ip arp"));
        assert_eq!(value.get("kind").and_then(Value::as_str), Some("setting"));
        assert_eq!(value.get("prefix_no").and_then(Value::as_bool), Some(true));
        assert!(
            value
                .pointer("/schema/properties/mac")
                .is_some_and(Value::is_object),
            "schema lists the mac argument: {value}"
        );
        lab.stop().await
    }

    /// Unknown schemes, versions and paths are typed `invalid_arguments` errors.
    #[tokio::test]
    async fn unknown_uris_are_invalid_arguments() -> TestResult {
        let lab = scoped_lab().await?;
        for uri in [
            "kcc://nowhere/lab-1",
            "kcc://catalog/9.9/ip%20arp",
            "kcc://catalog/5.1/no%20such%20command",
        ] {
            assert_eq!(
                read(&lab, uri).await?,
                Err("invalid_arguments".to_owned()),
                "{uri}"
            );
        }
        lab.stop().await
    }
}
