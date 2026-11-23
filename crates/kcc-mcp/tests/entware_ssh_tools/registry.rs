//! The registry entries of the `entware-ssh` toolset: the safety mark, the tools' hints,
//! permission and operations, and no enrolment tool anywhere.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the registry"
)]
mod tests {
    use kcc_app::permissions::Permission;
    use kcc_mcp::registry::definitions::{tools, toolset};
    use serde_json::json;

    use crate::support::{PACKAGES, SERVICES, TestResult};

    /// Todo 17: `entware-ssh` is a safety-reducing toolset (the Web asks for the password
    /// before turning it on) and `entware` is not.
    #[test]
    fn the_toolset_reduces_safety() -> TestResult {
        let info = toolset("entware-ssh").ok_or("no entware-ssh toolset")?;
        assert_eq!((info.name, info.safety_reducing), ("entware-ssh", true));
        assert!(
            !toolset("entware")
                .ok_or("no entware toolset")?
                .safety_reducing
        );
        Ok(())
    }

    /// Todo 17: both tools are in `entware-ssh`, need `Destructive`, are destructive-hinted
    /// and never read-only or idempotent, and take exactly their six operations.
    #[test]
    fn both_tools_are_destructive_with_their_operations() -> TestResult {
        let all = tools();
        for (name, ops) in [
            (
                PACKAGES,
                vec![
                    "list",
                    "upgradable",
                    "update",
                    "install",
                    "remove",
                    "upgrade",
                ],
            ),
            (
                SERVICES,
                vec!["list", "status", "start", "stop", "restart", "log"],
            ),
        ] {
            let tool = all
                .iter()
                .find(|tool| tool.name == name)
                .ok_or_else(|| format!("no {name}"))?;
            assert_eq!(
                (
                    tool.toolset,
                    tool.permission,
                    tool.read_only,
                    tool.destructive,
                    tool.idempotent,
                    tool.ops.clone(),
                ),
                (
                    "entware-ssh",
                    Permission::Destructive,
                    false,
                    true,
                    false,
                    ops
                ),
                "{name}"
            );
            assert_eq!(
                tool.annotations(),
                json!({
                    "readOnlyHint": false,
                    "destructiveHint": true,
                    "idempotentHint": false,
                    "openWorldHint": false
                }),
                "{name}"
            );
        }
        let ssh = all.iter().filter(|tool| tool.toolset == "entware-ssh");
        assert_eq!(ssh.count(), 2);
        Ok(())
    }

    /// Todo 17: no registered tool probes, bootstraps, re-pins or revokes: enrolment never
    /// runs over MCP, so the Entware password never passes through a model provider.
    #[test]
    fn no_tool_enrols() {
        for tool in tools() {
            let text = format!("{} {}", tool.name, tool.ops.join(" ")).to_ascii_lowercase();
            for word in ["probe", "bootstrap", "repin", "re_pin", "revoke"] {
                assert!(!text.contains(word), "{}: {word}", tool.name);
            }
        }
    }
}
