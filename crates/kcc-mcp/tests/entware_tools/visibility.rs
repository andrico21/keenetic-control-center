//! Which sessions see the Entware tools: the `entware` toolset, read-only mode, the live
//! gates, the tool metadata and the coarse permission.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the listed tools and the refusals"
)]
mod tests {
    use alloc::collections::BTreeSet;

    use kcc_app::{
        permissions::{Permission, Role},
        settings::McpConfig,
    };
    use kcc_mcp::registry::definitions::{tools, toolset};
    use serde_json::{Value, json};

    use crate::{
        helpers::{every, lab_on, refused_quietly, settings, unknown_tool},
        lab::{Lab, TestResult, admin},
    };

    /// The read tool.
    const READ: &str = "kcc_entware_read";
    /// The write tool.
    const WRITE: &str = "kcc_entware_write";

    /// A status read of `lab-1`.
    fn status() -> Value {
        json!({"host": "lab-1", "op": "status"})
    }

    /// A chroot change of `lab-1`.
    fn chroot() -> Value {
        json!({"host": "lab-1", "op": "chroot", "enabled": true})
    }

    /// Which of the two Entware tools `lab` lists.
    async fn listed(lab: &Lab) -> TestResult<(bool, bool)> {
        let names = lab.tool_names().await?;
        Ok((names.contains(READ), names.contains(WRITE)))
    }

    /// Todo 14: with the default `toolsets` (`core`) neither Entware tool is listed or
    /// callable.
    #[tokio::test]
    async fn entware_tools_are_absent_with_the_default_toolsets() -> TestResult {
        let lab = lab_on(McpConfig::default(), admin()).await?;

        assert_eq!(listed(&lab).await?, (false, false));
        assert!(unknown_tool(&lab, READ, status()).await?);
        assert!(unknown_tool(&lab, WRITE, chroot()).await?);
        lab.stop().await
    }

    /// Todo 14: the `entware` toolset alone registers both tools; the write tool takes
    /// exactly the six operations, and the installer is only the `arch` enum, never a URL.
    #[tokio::test]
    async fn the_entware_toolset_registers_both_tools() -> TestResult {
        let lab = lab_on(settings(&["entware"], false), admin()).await?;

        assert_eq!(listed(&lab).await?, (true, true));
        let listed_tools = lab.client.list_all_tools().await?;
        let write = listed_tools
            .iter()
            .find(|tool| tool.name == WRITE)
            .ok_or("no write tool")?;
        let schema = Value::Object((*write.input_schema).clone());
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .ok_or("no properties")?
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            properties,
            BTreeSet::from([
                "host", "op", "confirm", "drive", "arch", "enabled", "timezone", "initrc"
            ])
        );
        assert_eq!(
            schema.pointer("/properties/op/enum"),
            Some(&json!([
                "setup",
                "chroot",
                "timezone",
                "initrc",
                "dns_override",
                "remove"
            ]))
        );
        let arch = serde_json::to_string(&schema)?;
        for installer in ["aarch64", "mipsel", "mips"] {
            assert!(arch.contains(&format!("\"{installer}\"")), "{installer}");
        }
        assert!(!arch.contains("bin.entware.net"), "{arch}");
        assert_eq!(schema.get("additionalProperties"), Some(&json!(false)));
        lab.stop().await
    }

    /// Todo 14: in read-only mode the write tool is absent and refused as unknown; the read
    /// tool stays.
    #[tokio::test]
    async fn the_write_tool_is_absent_in_read_only_mode() -> TestResult {
        let mut config = every(true);
        config.read_only = true;
        let lab = lab_on(config, admin()).await?;

        assert_eq!(listed(&lab).await?, (true, false));
        assert!(unknown_tool(&lab, WRITE, chroot()).await?);
        lab.stop().await
    }

    /// Todo 14: an open session that listed the Entware tools is refused them at its
    /// next call once the live gates drop the toolset, and the write tool once they turn
    /// read-only.
    #[tokio::test]
    async fn a_tightening_reaches_an_open_session_at_its_next_call() -> TestResult {
        let lab = lab_on(every(true), admin()).await?;
        assert_eq!(listed(&lab).await?, (true, true));

        let mut read_only = every(true);
        read_only.read_only = true;
        lab.server.reconfigured(read_only).publish_gates();
        assert!(unknown_tool(&lab, WRITE, chroot()).await?);
        assert_eq!(listed(&lab).await?, (true, false));

        let mut without = every(true);
        without.toolsets.retain(|name| name != "entware");
        lab.server.reconfigured(without).publish_gates();
        assert!(unknown_tool(&lab, READ, status()).await?);
        assert_eq!(listed(&lab).await?, (false, false));
        lab.stop().await
    }

    /// Todo 14: the `entware` toolset does not reduce safety, and the registry gives the
    /// read tool `Read` (read-only) and the write tool `Write` (destructive-hinted) as the
    /// coarse permission RBAC is built from.
    #[test]
    fn the_registry_declares_the_toolset_and_the_tool_permissions() -> TestResult {
        let info = toolset("entware").ok_or("no entware toolset")?;
        assert!(!info.safety_reducing);
        let all = tools();
        let read = all.iter().find(|tool| tool.name == READ).ok_or("no read")?;
        let write = all
            .iter()
            .find(|tool| tool.name == WRITE)
            .ok_or("no write")?;
        assert_eq!(
            (
                read.toolset,
                read.permission,
                read.read_only,
                read.destructive
            ),
            ("entware", Permission::Read, true, false)
        );
        assert_eq!(
            (
                write.toolset,
                write.permission,
                write.read_only,
                write.destructive
            ),
            ("entware", Permission::Write, false, true)
        );
        Ok(())
    }

    /// Todo 14: a role with `Read` only is offered the read tool, not the write tool, and
    /// a write call is forbidden before the router is contacted.
    #[tokio::test]
    async fn a_read_only_role_gets_the_read_tool_only() -> TestResult {
        let viewer = Role::new(
            "entware-viewer".to_owned(),
            [Permission::Read],
            vec!["*".to_owned()],
        );
        let lab = lab_on(every(true), viewer).await?;

        assert_eq!(listed(&lab).await?, (true, false));
        refused_quietly(&lab, (WRITE, chroot()), "forbidden").await?;
        assert_eq!(
            lab.call(READ, status(), false).await?.error(),
            None,
            "the read tool works"
        );
        lab.stop().await
    }

    /// Todo 14: a role scoped to other routers is refused both Entware tools on `lab-1` as
    /// `forbidden` before the router is contacted.
    #[tokio::test]
    async fn a_role_scoped_to_other_routers_is_forbidden_both_tools() -> TestResult {
        let other = Role::new(
            "other".to_owned(),
            Permission::ALL,
            vec!["other-*".to_owned()],
        );
        let lab = lab_on(every(true), other).await?;

        refused_quietly(&lab, (READ, status()), "forbidden").await?;
        refused_quietly(&lab, (WRITE, chroot()), "forbidden").await?;
        lab.stop().await
    }
}
