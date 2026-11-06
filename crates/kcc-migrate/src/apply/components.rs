//! Explicit prerequisite installation before a fresh migration plan is reviewed.

use core::time::Duration;

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, TerminalCliChangeRequest},
};
use kcc_catalog::HttpMethod;
use kcc_domain::{
    RouterCtx,
    configuration::{SafetyMode, SafetyNet},
};
use serde_json::json;

use super::{ApplyError, ApplyRequest};
use crate::inventory::{InventoryClient, TargetInventory};

/// Installs approved prerequisites under recovery, then forces review of a new inventory.
///
/// # Errors
/// Returns prerequisite validation, workflow, or reconnect failures. Success returns
/// `ReplanRequired`: an earlier executable plan is never applied to the changed firmware.
// NOT cancel-safe: component commit reboots the target and changes installed firmware.
pub(super) async fn install(
    request: &ApplyRequest,
    changes: &mut ChangeSet,
    ctx: &RouterCtx,
) -> Result<(), ApplyError> {
    if request.options.install_components.is_empty() {
        return Ok(());
    }
    let mut commands = Vec::new();
    for name in &request.options.install_components {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ApplyError::Validation);
        }
        let validated = ctx
            .catalog
            .validate(
                "components install",
                HttpMethod::Post,
                &json!({"component":name}),
            )
            .map_err(|_issues| ApplyError::Validation)?;
        commands.push(ValidatedCli::new(
            format!("components install {name}"),
            validated,
        ));
    }
    let validated = ctx
        .catalog
        .validate("components commit", HttpMethod::Post, &json!({}))
        .map_err(|_issues| ApplyError::Validation)?;
    for command in commands {
        drop(
            changes
                .apply_cli(CliChangeRequest::new(
                    vec![command],
                    Vec::new(),
                    Permission::Destructive,
                    json!({"prerequisite":true}),
                ))
                .await
                .map_err(|_error| ApplyError::Workflow)?,
        );
    }
    drop(
        changes
            .apply_cli_terminal(TerminalCliChangeRequest::new(
                vec![ValidatedCli::new("components commit".to_owned(), validated)],
                Permission::Destructive,
                json!({"prerequisite":true}),
            ))
            .await
            .map_err(|_error| ApplyError::Workflow)?,
    );
    for _attempt in 0..120_u16 {
        request.options.clock.wait(Duration::from_secs(1)).await;
        if changes
            .reconnect(ctx.client.router_url().clone(), None)
            .await
            .is_err()
        {
            continue;
        }
        let client = changes.client();
        let info = client
            .detect()
            .await
            .map_err(|_error| ApplyError::Unreachable)?;
        if !request
            .options
            .install_components
            .iter()
            .all(|name| info.components.contains(name))
        {
            return Err(ApplyError::Verification);
        }
        let source_version = request.options.source_firmware.or(info.firmware);
        let inventory =
            TargetInventory::collect(&InventoryClient::from_client(&client), source_version)
                .await
                .map_err(|_error| ApplyError::Verification)?;
        let mode = if inventory.fail_safe_available {
            SafetyMode::Router
        } else {
            SafetyMode::ScheduledReboot
        };
        let updated = RouterCtx::new(client, inventory.catalog);
        drop(
            SafetyNet::arm(changes, &updated, mode, request.options.safety_seconds)
                .await
                .map_err(|_error| ApplyError::Workflow)?,
        );
        return Err(ApplyError::ReplanRequired);
    }
    Err(ApplyError::Unreachable)
}
