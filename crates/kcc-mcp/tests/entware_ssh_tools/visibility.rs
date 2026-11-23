//! Which sessions see the `entware-ssh` tools: the toolset, read-only mode, the closed
//! input schemas, and a tightening of the live gates in an open session.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the listed tools and the refusals"
)]
mod tests {
    use kcc_app::settings::McpConfig;
    use serde_json::{Value, json};

    use crate::{
        rig::Rig,
        support::{EVERY, PACKAGES, SERVICES, Setup, TestResult, admin, every, settings},
    };

    /// A package listing of `lab-1`.
    fn list() -> Value {
        json!({"host": "lab-1", "op": "list", "confirm": true})
    }

    /// Which of the two tools `rig` lists.
    async fn listed(rig: &Rig) -> TestResult<(bool, bool)> {
        let names = rig.tool_names().await?;
        Ok((names.contains(PACKAGES), names.contains(SERVICES)))
    }

    /// Todo 17: with the default `toolsets` (`core`) neither tool is listed or callable.
    #[tokio::test]
    async fn absent_with_the_default_toolsets() -> TestResult {
        let rig = Rig::start(Setup::new(McpConfig::default(), admin())).await?;
        assert_eq!(listed(&rig).await?, (false, false));
        assert!(rig.unknown(PACKAGES, list()).await?);
        assert!(rig.unknown(SERVICES, list()).await?);
        rig.stop().await
    }

    /// Todo 17: read-only mode hides both tools even with `entware-ssh` on, since every
    /// operation (reads included) is destructive.
    #[tokio::test]
    async fn absent_in_read_only_mode_with_the_toolset() -> TestResult {
        let mut config = settings(&["core", "entware-ssh"], true);
        config.read_only = true;
        let rig = Rig::start(Setup::new(config, admin())).await?;
        assert_eq!(listed(&rig).await?, (false, false));
        assert!(rig.unknown(PACKAGES, list()).await?);
        assert!(rig.unknown(SERVICES, list()).await?);
        rig.stop().await
    }

    /// Todo 17: `entware-ssh` alone lists both tools with closed input schemas.
    ///
    /// Both are destructive-hinted; the six operations are an enum, and there is no other
    /// property than the documented ones: no password, command or URL input.
    #[tokio::test]
    async fn the_toolset_lists_both_tools_with_closed_schemas() -> TestResult {
        let rig = Rig::start(Setup::new(settings(&["entware-ssh"], true), admin())).await?;
        assert_eq!(listed(&rig).await?, (true, true));
        for (name, ops, properties) in [
            (
                PACKAGES,
                json!([
                    "list",
                    "upgradable",
                    "update",
                    "install",
                    "remove",
                    "upgrade"
                ]),
                ["confirm", "cursor", "host", "op", "package"].as_slice(),
            ),
            (
                SERVICES,
                json!(["list", "status", "start", "stop", "restart", "log"]),
                ["confirm", "cursor", "host", "max_lines", "op", "service"].as_slice(),
            ),
        ] {
            let tool = rig.listed(name).await?;
            let annotations = tool.annotations.clone().ok_or("no annotations")?;
            assert_eq!(
                (annotations.read_only_hint, annotations.destructive_hint),
                (Some(false), Some(true)),
                "{name}"
            );
            let schema = Value::Object((*tool.input_schema).clone());
            assert_eq!(schema.get("additionalProperties"), Some(&json!(false)));
            assert_eq!(schema.pointer("/properties/op/enum"), Some(&ops), "{name}");
            let mut keys = schema
                .get("properties")
                .and_then(Value::as_object)
                .ok_or("no properties")?
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            keys.sort_unstable();
            assert_eq!(keys, properties, "{name}");
        }
        rig.stop().await
    }

    /// Todo 17: a tightening of the live gates binds an open session at its next call.
    ///
    /// Destructive operations off refuses the call before any contact, and dropping the
    /// toolset or turning read-only mode on removes the tools.
    #[tokio::test]
    async fn a_tightening_applies_to_an_open_session() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        let first = rig.call(PACKAGES, list()).await?;
        assert_eq!(first.ok()?.get("op"), Some(&json!("list")));

        let mut destructive_off = every();
        destructive_off.allow_destructive = false;
        rig.server().reconfigured(destructive_off).publish_gates();
        rig.refused_quietly((PACKAGES, list()), "destructive_disabled")
            .await?;
        rig.refused_quietly((SERVICES, list()), "destructive_disabled")
            .await?;

        let mut read_only = every();
        read_only.read_only = true;
        rig.server().reconfigured(read_only).publish_gates();
        assert!(rig.unknown(PACKAGES, list()).await?);
        assert_eq!(listed(&rig).await?, (false, false));

        let without = settings(
            &EVERY
                .into_iter()
                .filter(|name| *name != "entware-ssh")
                .collect::<Vec<_>>(),
            true,
        );
        rig.server().reconfigured(without).publish_gates();
        assert!(rig.unknown(SERVICES, list()).await?);
        rig.stop().await
    }
}
