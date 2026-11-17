//! Synthetic operation coverage of the shared curated apply boundary.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::absolute_paths,
    reason = "test fixture and acceptance assertions are local to this test module"
)]

use kcc_app::{
    settings::{McpConfig, PrivacyConfig},
    workflow::ChangeResult,
};
use kcc_catalog::Risk;
use kcc_domain::{services, system};

use super::{apply, apply_cli, apply_registered, open};
use crate::{McpFailure, domains::table::Area, support::errors::map_workflow, tests::fixture};

/// A new management operation is bracketed regardless of its domain descriptor.
// NOT cancel-safe: the fixture owns router tasks and transmitted changes.
#[tokio::test]
async fn synthetic_management_operation_brackets_both_apply_entries()
-> Result<(), Box<dyn core::error::Error>> {
    let mut missing = Vec::new();
    for entry in ["direct", "cli", "registered"] {
        let mut config = McpConfig::default();
        config.allow_destructive = true;
        let fixture = fixture::Fixture::spawn(config, PrivacyConfig::default()).await?;
        let server = fixture.server();
        let opened = open(server, Area::System, ("lab-1".to_owned(), "hostname", true))
            .await
            .map_err(failure)?;
        let before = fixture.commands().len();
        if entry == "cli" {
            let mut operation = services::plan_service(&opened.2, "iperf3", true)?;
            operation.risk = Risk::Management;
            drop(
                apply_cli(
                    server,
                    &opened,
                    (Ok(operation), true, services::change_request),
                )
                .await
                .map_err(failure)?,
            );
        } else {
            let mut operation = system::plan_hostname(&opened.2, "synthetic-management")?;
            operation.risk = Risk::Management;
            let request = system::change_request(&operation)?;
            let work = async |changes: &mut kcc_app::workflow::ChangeSet| {
                changes.apply(request).await.map_err(map_workflow)
            };
            let _applied: ChangeResult = if entry == "registered" {
                apply_registered(
                    server,
                    &opened,
                    (Area::Services, "management_port", true, work),
                )
                .await
            } else {
                apply(server, &opened, (&operation, true, work)).await
            }
            .map_err(failure)?;
        }
        let commands = fixture
            .commands()
            .into_iter()
            .skip(before)
            .collect::<Vec<_>>();
        if commands.first().map(String::as_str)
            != Some("system configuration fail-safe timer reboot 300")
            || commands.last().map(String::as_str)
                != Some("no system configuration fail-safe timer")
        {
            missing.push(format!("{entry}: {}", commands.join("; ")));
        }
        fixture.shutdown().await?;
    }
    assert!(
        missing.is_empty(),
        "entries missing management recovery: {missing:?}"
    );
    Ok(())
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "used as a `map_err` callback, which hands over the failure by value"
)]
fn failure(error: McpFailure) -> String {
    format!("MCP failure: {error:?}")
}
