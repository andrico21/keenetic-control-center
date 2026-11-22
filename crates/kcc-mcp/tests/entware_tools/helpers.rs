//! Shared steps of the Entware tool tests.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of the step that failed"
)]

use kcc_app::{
    permissions::Role,
    settings::{McpConfig, PrivacyConfig},
};
use kcc_testkit::{FakeRouter, model::Profile};
use rmcp::{ServiceError, model::CallToolRequestParams};
use serde_json::Value;

use crate::lab::{Lab, TOOLSETS, TestResult};

/// `[mcp]` settings registering `toolsets`, with destructive operations
/// `allow_destructive`.
pub(crate) fn settings(toolsets: &[&str], allow_destructive: bool) -> McpConfig {
    let mut config = McpConfig::default();
    config.toolsets = toolsets.iter().map(|&name| name.to_owned()).collect();
    config.allow_destructive = allow_destructive;
    config
}

/// Every toolset, with destructive operations `allow_destructive`.
pub(crate) fn every(allow_destructive: bool) -> McpConfig {
    settings(&TOOLSETS, allow_destructive)
}

/// A session with `role` on one KN-1811 `lab-1` under `config`.
pub(crate) async fn lab_on(config: McpConfig, role: Role) -> TestResult<Lab> {
    lab_with(
        FakeRouter::builder(Profile::default()).build()?,
        config,
        role,
    )
    .await
}

/// A session with `role` on the router `lab-1` under `config`.
pub(crate) async fn lab_with(router: FakeRouter, config: McpConfig, role: Role) -> TestResult<Lab> {
    Lab::start_with_settings(
        vec![("lab-1", router)],
        role,
        (config, PrivacyConfig::default()),
    )
    .await
}

/// Every parser line `lab-1` received, in order.
pub(crate) fn lines(lab: &Lab) -> TestResult<Vec<String>> {
    Ok(lab
        .router("lab-1")?
        .request_log()
        .iter()
        .flat_map(|record| {
            record
                .commands()
                .flatten()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect())
}

/// Whether the session refuses `tool` as unknown, the refusal of a tool the gates do not
/// admit.
pub(crate) async fn unknown_tool(lab: &Lab, tool: &str, arguments: Value) -> TestResult<bool> {
    let Value::Object(object) = arguments else {
        return Err("arguments must be an object".into());
    };
    let request = CallToolRequestParams::new(tool.to_owned()).with_arguments(object);
    match lab.client.call_tool(request).await {
        Err(ServiceError::McpError(error)) => Ok(error.message == "tool not found"),
        Err(other) => Err(other.into()),
        Ok(_result) => Ok(false),
    }
}

/// Fails unless `call` (tool and arguments) is refused with `code` while `lab-1` receives
/// no request.
pub(crate) async fn refused_quietly(lab: &Lab, call: (&str, Value), code: &str) -> TestResult {
    let (tool, arguments) = call;
    let before = lab.requests("lab-1")?;
    let reply = lab.call(tool, arguments.clone(), false).await?;
    if reply.error() != Some(code) {
        return Err(format!("{tool} {arguments}: expected {code}, got {reply:?}").into());
    }
    let after = lab.requests("lab-1")?;
    if after != before {
        return Err(format!("{tool} {arguments}: requests {before} -> {after}").into());
    }
    Ok(())
}
