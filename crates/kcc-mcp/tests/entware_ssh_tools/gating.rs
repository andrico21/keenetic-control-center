//! The safety gates of every operation and the boundary checks, each refused before the
//! router or the SSH server is contacted.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "acceptance tests assert the refusals"
)]
mod tests {
    use kcc_app::permissions::{Permission, Role};
    use serde_json::{Value, json};

    use crate::{
        rig::Rig,
        support::{EVERY, PACKAGES, SERVICES, Setup, TestResult, admin, every, settings},
    };

    /// Every operation of both tools with valid arguments and no confirmation.
    fn operations() -> Vec<(&'static str, Value)> {
        let package = |op: &str| json!({"host": "lab-1", "op": op, "package": "htop"});
        let service = |op: &str| json!({"host": "lab-1", "op": op, "service": "S50nginx"});
        let bare = |op: &str| json!({"host": "lab-1", "op": op});
        vec![
            (PACKAGES, bare("list")),
            (PACKAGES, bare("upgradable")),
            (PACKAGES, bare("update")),
            (PACKAGES, package("install")),
            (PACKAGES, package("remove")),
            (PACKAGES, package("upgrade")),
            (SERVICES, bare("list")),
            (SERVICES, service("status")),
            (SERVICES, service("start")),
            (SERVICES, service("stop")),
            (SERVICES, service("restart")),
            (SERVICES, service("log")),
        ]
    }

    /// `arguments` with `member` set to `value`.
    fn with(mut arguments: Value, member: &str, value: Value) -> Value {
        if let Value::Object(object) = &mut arguments {
            drop(object.insert(member.to_owned(), value));
        }
        arguments
    }

    /// Todo 17: with `allow_destructive` off every operation, reads included, is refused
    /// `destructive_disabled` even when confirmed.
    #[tokio::test]
    async fn every_operation_needs_the_server_switch() -> TestResult {
        let rig = Rig::start(Setup::new(settings(&EVERY, false), admin())).await?;
        for (tool, arguments) in operations() {
            let confirmed = with(arguments, "confirm", json!(true));
            rig.refused_quietly((tool, confirmed), "destructive_disabled")
                .await?;
        }
        rig.stop().await
    }

    /// Todo 17: every operation, reads included, without `confirm: true` (absent or false)
    /// is refused `confirm_required`.
    #[tokio::test]
    async fn every_operation_needs_confirmation() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        for (tool, arguments) in operations() {
            let declined = with(arguments.clone(), "confirm", json!(false));
            rig.refused_quietly((tool, arguments), "confirm_required")
                .await?;
            rig.refused_quietly((tool, declined), "confirm_required")
                .await?;
        }
        rig.stop().await
    }

    /// Todo 17: a role with every permission but `Destructive` (`Write` included) is not
    /// offered the tools, and every operation it calls is `forbidden` with no contact.
    #[tokio::test]
    async fn every_operation_needs_destructive() -> TestResult {
        let operator = Role::new(
            "operator".to_owned(),
            Permission::ALL
                .into_iter()
                .filter(|permission| *permission != Permission::Destructive),
            vec!["*".to_owned()],
        );
        let rig = Rig::start(Setup::new(every(), operator)).await?;
        let names = rig.tool_names().await?;
        assert!(!names.contains(PACKAGES) && !names.contains(SERVICES));
        for (tool, arguments) in operations() {
            let confirmed = with(arguments, "confirm", json!(true));
            rig.refused_quietly((tool, confirmed), "forbidden").await?;
        }
        rig.stop().await
    }

    /// Todo 17: a role scoped to other routers is `forbidden` on `lab-1` for every
    /// operation of both tools, with no contact.
    #[tokio::test]
    async fn a_role_scoped_to_other_routers_is_forbidden() -> TestResult {
        let elsewhere = Role::new(
            "elsewhere".to_owned(),
            Permission::ALL,
            vec!["prod-*".to_owned()],
        );
        let rig = Rig::start(Setup::new(every(), elsewhere)).await?;
        for (tool, arguments) in operations() {
            let confirmed = with(arguments, "confirm", json!(true));
            rig.refused_quietly((tool, confirmed), "forbidden").await?;
        }
        rig.stop().await
    }

    /// Todo 17: hostile package and service names (space, newline, `;`, `../`, a URL,
    /// over-long, upper case, outside the init script pattern) are `invalid_arguments`
    /// before any contact.
    #[tokio::test]
    async fn hostile_names_are_refused_before_any_contact() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        let long_package = "a".repeat(65);
        let long_service = format!("S50{}", "a".repeat(49));
        let packages = [
            "",
            "nano htop",
            "nano\nreboot",
            "nano;reboot",
            "../etc/passwd",
            "https://evil.example/p.ipk",
            long_package.as_str(),
            "Nano",
            "-nano",
            "nano'",
        ];
        for op in ["install", "remove", "upgrade"] {
            for name in packages {
                let call = json!({"host": "lab-1", "op": op, "confirm": true, "package": name});
                rig.refused_quietly((PACKAGES, call), "invalid_arguments")
                    .await?;
            }
        }
        let services = [
            "",
            "S50 nginx",
            "S50nginx\nreboot",
            "S50nginx;reboot",
            "../S50nginx",
            "S50../../bin/sh",
            "https://evil.example/S50x",
            long_service.as_str(),
            "nginx",
            "S5nginx",
        ];
        for op in ["status", "start", "stop", "restart", "log"] {
            for name in services {
                let call = json!({"host": "lab-1", "op": op, "confirm": true, "service": name});
                rig.refused_quietly((SERVICES, call), "invalid_arguments")
                    .await?;
            }
        }
        rig.stop().await
    }

    /// Todo 17: malformed calls are `invalid_arguments` before any contact.
    ///
    /// An unknown operation, an extra property, a missing or superfluous name, a
    /// non-decimal cursor, a cursor on a single-value operation and a log length outside
    /// 1 to 1000.
    #[tokio::test]
    async fn malformed_calls_are_refused_before_any_contact() -> TestResult {
        let rig = Rig::start(Setup::new(every(), admin())).await?;
        let calls = [
            (PACKAGES, json!({"op": "shell"})),
            (PACKAGES, json!({"op": "probe"})),
            (PACKAGES, json!({"op": "list", "command": "reboot"})),
            (PACKAGES, json!({"op": "list", "password": "keenetic"})),
            (PACKAGES, json!({"op": "list", "package": "nano"})),
            (PACKAGES, json!({"op": "install"})),
            (PACKAGES, json!({"op": "list", "cursor": "x"})),
            (PACKAGES, json!({"op": "list", "cursor": "-1"})),
            (
                PACKAGES,
                json!({"op": "install", "package": "htop", "cursor": "1"}),
            ),
            (SERVICES, json!({"op": "bootstrap"})),
            (SERVICES, json!({"op": "list", "service": "S50nginx"})),
            (SERVICES, json!({"op": "start"})),
            (
                SERVICES,
                json!({"op": "status", "service": "S50nginx", "cursor": "1"}),
            ),
            (
                SERVICES,
                json!({"op": "status", "service": "S50nginx", "max_lines": 5_u32}),
            ),
            (
                SERVICES,
                json!({"op": "log", "service": "S50nginx", "max_lines": 0_u32}),
            ),
            (
                SERVICES,
                json!({"op": "log", "service": "S50nginx", "max_lines": 1001_u32}),
            ),
            (SERVICES, json!({"op": "list", "package": "nano"})),
        ];
        for (tool, call) in calls {
            let full = with(with(call, "host", json!("lab-1")), "confirm", json!(true));
            rig.refused_quietly((tool, full), "invalid_arguments")
                .await?;
        }
        rig.stop().await
    }
}
