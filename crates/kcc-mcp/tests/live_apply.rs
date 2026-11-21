//! Live MCP settings over real sessions: a reconfigured handler's tightening binds the
//! sessions already open at their next call, a loosening only new sessions, and the
//! migration plans outlive the reconfiguration.
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
    reason = "acceptance assertions establish the live settings contract"
)]
mod tests {
    use alloc::sync::Arc;
    use core::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use kcc_app::settings::McpConfig;
    use kcc_mcp::KccMcp;
    use kcc_testkit::{FakeRouter, migration, model::Profile};
    use rmcp::{
        ServiceError, ServiceExt as _,
        model::CallToolRequestParams,
        service::{Peer, RoleClient, RunningService},
    };
    use serde_json::{Value, json};
    use tokio::{
        io::duplex,
        sync::Barrier,
        task::{JoinSet, yield_now},
        time::timeout,
    };

    use super::lab::{Lab, TestResult, admin};

    /// The toolsets every lab session starts with.
    const TOOLSETS: [&str; 8] = [
        "core",
        "network-write",
        "vpn",
        "dns",
        "system-admin",
        "migration",
        "presets",
        "raw",
    ];

    /// How one tool call ended.
    #[derive(Debug, PartialEq)]
    enum Outcome {
        /// The tool answered with this result.
        Done(Value),
        /// The tool refused with this error code.
        Code(String),
        /// The server refused the request with this protocol error message.
        Refused(String),
    }

    /// The lab's settings with `allow_destructive`.
    fn settings(allow_destructive: bool) -> McpConfig {
        let mut config = McpConfig::default();
        config.toolsets = TOOLSETS.map(str::to_owned).to_vec();
        config.allow_destructive = allow_destructive;
        config
    }

    /// A reboot of `lab-1` without confirmation: `confirm_required` while destructive
    /// operations are on, `destructive_disabled` while they are off.
    fn reboot() -> Value {
        json!({"host": "lab-1", "op": "reboot"})
    }

    /// A lab with one plain router `lab-1` and destructive operations `on`.
    async fn lab(on: bool) -> TestResult<Lab> {
        Lab::start_with_destructive(
            vec![("lab-1", FakeRouter::builder(Profile::default()).build()?)],
            admin(),
            on,
        )
        .await
    }

    /// A new stdio session on `server`.
    async fn session(server: KccMcp) -> TestResult<RunningService<RoleClient, ()>> {
        let (server_io, client_io) = duplex(1 << 20);
        drop(tokio::spawn(async move {
            if let Ok(running) = server.serve(server_io).await {
                drop(running.waiting().await);
            }
        }));
        Ok(().serve(client_io).await?)
    }

    /// Calls `tool` with `arguments` on `peer`.
    async fn call(peer: &Peer<RoleClient>, tool: &str, arguments: Value) -> TestResult<Outcome> {
        let Value::Object(object) = arguments else {
            return Err("arguments must be an object".into());
        };
        let request = CallToolRequestParams::new(tool.to_owned()).with_arguments(object);
        let result = match peer.call_tool(request).await {
            Ok(result) => result,
            Err(ServiceError::McpError(error)) => {
                return Ok(Outcome::Refused(error.message.into_owned()));
            }
            Err(other) => return Err(other.into()),
        };
        let text = result
            .content
            .first()
            .and_then(|content| content.as_text())
            .map(|content| content.text.clone())
            .ok_or("tool returned no text")?;
        let value: Value = serde_json::from_str(&text)?;
        if result.is_error == Some(true) {
            let code = value
                .get("error")
                .and_then(Value::as_str)
                .ok_or("no code")?;
            return Ok(Outcome::Code(code.to_owned()));
        }
        Ok(Outcome::Done(value))
    }

    /// The names of the tools `peer` lists.
    async fn listed(peer: &Peer<RoleClient>) -> TestResult<Vec<String>> {
        Ok(peer
            .list_all_tools()
            .await?
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect())
    }

    fn code(code: &str) -> Outcome {
        Outcome::Code(code.to_owned())
    }

    fn not_found() -> Outcome {
        Outcome::Refused("tool not found".to_owned())
    }

    /// Todo 25: an open session gets `destructive_disabled` at its next call once
    /// `allow_destructive` is turned off.
    #[tokio::test]
    async fn tightening_applies_to_open_sessions() -> TestResult {
        let lab = lab(true).await?;
        assert_eq!(
            call(&lab.client, "kcc_system_write", reboot()).await?,
            code("confirm_required")
        );

        lab.server.reconfigured(settings(false)).publish_gates();

        assert_eq!(
            call(&lab.client, "kcc_system_write", reboot()).await?,
            code("destructive_disabled")
        );
        lab.stop().await
    }

    /// Todo 25: turning `allow_destructive` on binds sessions opened on the reconfigured
    /// handler; a session opened before keeps its own, stricter setting.
    #[tokio::test]
    async fn loosening_applies_to_new_sessions() -> TestResult {
        let lab = lab(false).await?;
        assert_eq!(
            call(&lab.client, "kcc_system_write", reboot()).await?,
            code("destructive_disabled")
        );

        let next = lab.server.reconfigured(settings(true));
        next.publish_gates();
        let fresh = session(next).await?;

        assert_eq!(
            call(&lab.client, "kcc_system_write", reboot()).await?,
            code("destructive_disabled"),
            "the open session"
        );
        assert_eq!(
            call(&fresh, "kcc_system_write", reboot()).await?,
            code("confirm_required"),
            "the new session"
        );
        drop(fresh.cancel().await?);
        lab.stop().await
    }

    /// Todo 25: read-only mode turned on hides every write tool from an open session's
    /// next `tools/list` and refuses its next write call; reads go on.
    #[tokio::test]
    async fn read_only_applies_to_open_sessions() -> TestResult {
        let lab = lab(true).await?;
        assert!(
            listed(&lab.client)
                .await?
                .contains(&"kcc_system_write".to_owned())
        );

        let mut read_only = settings(true);
        read_only.read_only = true;
        lab.server.reconfigured(read_only).publish_gates();

        let tools = listed(&lab.client).await?;
        assert!(!tools.contains(&"kcc_system_write".to_owned()), "{tools:?}");
        assert!(tools.contains(&"kcc_routers_list".to_owned()), "{tools:?}");
        assert_eq!(
            call(&lab.client, "kcc_system_write", reboot()).await?,
            not_found()
        );
        assert!(matches!(
            call(&lab.client, "kcc_routers_list", json!({})).await?,
            Outcome::Done(_)
        ));
        lab.stop().await
    }

    /// Todo 25: a toolset turned off disappears from an open session's next
    /// `tools/list`, and its tools are refused as unknown.
    #[tokio::test]
    async fn a_removed_toolset_leaves_open_sessions() -> TestResult {
        let lab = lab(true).await?;
        assert!(
            listed(&lab.client)
                .await?
                .contains(&"kcc_rci_execute".to_owned())
        );

        let mut without_raw = settings(true);
        without_raw.toolsets.retain(|toolset| toolset != "raw");
        lab.server.reconfigured(without_raw).publish_gates();

        let tools = listed(&lab.client).await?;
        assert!(!tools.contains(&"kcc_rci_execute".to_owned()), "{tools:?}");
        assert!(tools.contains(&"kcc_system_write".to_owned()), "{tools:?}");
        assert_eq!(
            call(
                &lab.client,
                "kcc_rci_execute",
                json!({"host": "lab-1", "path": "system/name", "value": "x"})
            )
            .await?,
            not_found()
        );
        lab.stop().await
    }

    /// Todo 25: a lowered `max_result_bytes` cuts an open session's next result.
    #[tokio::test]
    async fn a_lowered_result_cap_applies_at_the_next_call() -> TestResult {
        const CAP: u32 = 100;
        let mut routers = Vec::new();
        for id in ["lab-1", "lab-2", "lab-3"] {
            routers.push((id, FakeRouter::builder(Profile::default()).build()?));
        }
        let lab = Lab::start(routers, admin()).await?;
        let Outcome::Done(whole) = call(&lab.client, "kcc_routers_list", json!({})).await? else {
            return Err("the list failed".into());
        };
        assert!(whole.get("truncated").is_none(), "{whole}");
        assert!(whole.to_string().len() > usize::try_from(CAP)?, "{whole}");

        let mut capped = settings(true);
        capped.max_result_bytes = CAP;
        lab.server.reconfigured(capped).publish_gates();

        let Outcome::Done(cut) = call(&lab.client, "kcc_routers_list", json!({})).await? else {
            return Err("the capped list failed".into());
        };
        assert_eq!(cut.get("truncated"), Some(&json!(true)), "{cut}");
        assert!(cut.to_string().len() <= usize::try_from(CAP)?, "{cut}");
        lab.stop().await
    }

    /// A migration target in router mode.
    fn target() -> TestResult<FakeRouter> {
        let mut scenario = migration::Fixture::default();
        scenario.mode = Some("router".to_owned());
        Ok(FakeRouter::builder(Profile::default())
            .build()?
            .with_migration(scenario))
    }

    /// Plans `lab-src` onto `lab-1`; a blocked plan is planned again with every conflict
    /// taking the source's value and every other blocking setting left out.
    async fn plan(peer: &Peer<RoleClient>) -> TestResult<String> {
        let first = json!({"host": "lab-1", "source": "lab-src", "ack_documentation_tier": true});
        let Outcome::Done(mut value) = call(peer, "kcc_migration_plan", first).await? else {
            return Err("the plan failed".into());
        };
        if value.get("status") == Some(&json!("blocked")) {
            let blocked = value
                .get("blocked")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let indices = |conflict: bool| {
                blocked
                    .iter()
                    .filter(|item| {
                        (item.get("disposition") == Some(&json!("conflict"))) == conflict
                    })
                    .filter_map(|item| item.get("source_index").cloned())
                    .collect::<Vec<_>>()
            };
            let resolved = json!({
                "host": "lab-1",
                "source": "lab-src",
                "ack_documentation_tier": true,
                "overwrite": indices(true),
                "exclude": indices(false)
            });
            let Outcome::Done(planned) = call(peer, "kcc_migration_plan", resolved).await? else {
                return Err("the resolved plan failed".into());
            };
            value = planned;
        }
        assert_eq!(value.get("status"), Some(&json!("planned")), "{value}");
        Ok(value
            .get("plan_id")
            .and_then(Value::as_str)
            .ok_or("plan without id")?
            .to_owned())
    }

    /// Todo 25: a migration plan made before a reconfiguration is found by a session
    /// opened on the reconfigured handler.
    #[tokio::test]
    async fn migration_plan_survives_reconfigure() -> TestResult {
        let routers = vec![
            ("lab-src", FakeRouter::builder(Profile::default()).build()?),
            ("lab-1", target()?),
        ];
        let lab = Lab::start(routers, admin()).await?;
        let plan_id = plan(&lab.client).await?;

        let mut without_raw = settings(true);
        without_raw.toolsets.retain(|toolset| toolset != "raw");
        let next = lab.server.reconfigured(without_raw);
        next.publish_gates();
        let fresh = session(next).await?;

        let apply = |id: &str| json!({"host": "lab-1", "plan_id": id, "confirm": false});
        assert_eq!(
            call(&fresh, "kcc_migration_apply", apply(&plan_id)).await?,
            code("confirm_required"),
            "the plan is found"
        );
        assert_eq!(
            call(&fresh, "kcc_migration_apply", apply("no-such-plan")).await?,
            code("invalid_arguments"),
            "an unknown plan is not"
        );
        drop(fresh.cancel().await?);
        lab.stop().await
    }

    /// Todo 25: calls racing with alternating gates each run under one generation.
    ///
    /// Generation A (destructive on, `system-admin` on) answers `confirm_required`,
    /// generation B (both off) refuses the tool as unknown; a call admitted under A and
    /// refused under B's destructive switch would be a torn mix.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_calls_see_one_generation_of_gates() -> TestResult {
        const SESSIONS: usize = 6;
        const CALLS: usize = 20;
        let lab = lab(true).await?;
        let open = lab.server.reconfigured(settings(true));
        let mut closed_settings = settings(false);
        closed_settings
            .toolsets
            .retain(|toolset| toolset != "system-admin");
        let closed = lab.server.reconfigured(closed_settings);
        let barrier = Arc::new(Barrier::new(SESSIONS + 1));
        let finished = Arc::new(AtomicUsize::new(0));
        let mut calls = JoinSet::new();
        for _ in 0..SESSIONS {
            let client = session(lab.server.clone()).await?;
            let start = Arc::clone(&barrier);
            let done = Arc::clone(&finished);
            drop(calls.spawn(async move {
                let _leader = start.wait().await;
                let mut outcomes = Vec::new();
                for _ in 0..CALLS {
                    outcomes.push(
                        call(&client, "kcc_system_write", reboot())
                            .await
                            .map_err(|error| error.to_string()),
                    );
                }
                drop(client.cancel().await);
                let _before: usize = done.fetch_add(1, Ordering::SeqCst);
                outcomes
            }));
        }

        let _leader = barrier.wait().await;
        let flipping = async {
            for generation in [&closed, &open].into_iter().cycle() {
                if finished.load(Ordering::SeqCst) == SESSIONS {
                    break;
                }
                generation.publish_gates();
                yield_now().await;
            }
        };
        timeout(Duration::from_secs(60), flipping).await?;
        let mut seen = Vec::new();
        while let Some(joined) = calls.join_next().await {
            seen.extend(joined?);
        }
        open.publish_gates();

        assert_eq!(seen.len(), SESSIONS * CALLS);
        for result in seen {
            let outcome = result?;
            assert!(
                outcome == code("confirm_required") || outcome == not_found(),
                "{outcome:?}"
            );
        }
        lab.stop().await
    }
}
