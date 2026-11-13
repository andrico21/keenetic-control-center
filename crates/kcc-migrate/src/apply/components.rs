//! Explicit prerequisite installation before a fresh migration plan is reviewed.

use core::time::Duration;

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, TerminalCliChangeRequest},
};
use kcc_catalog::HttpMethod;
use kcc_domain::RouterCtx;
use serde_json::json;

use super::{ApplyError, ApplyRequest, settle::Stop};

/// Installs approved prerequisites under recovery, then forces review of a new inventory.
///
/// # Errors
/// Returns prerequisite validation, workflow, or reconnect failures as [`Stop::Armed`] until
/// `components commit` is sent, and as [`Stop::Rebooted`] after it. Success returns
/// `ReplanRequired` with nothing armed: the commit reboots the router onto its saved
/// configuration, which clears the recovery timer, and an earlier executable plan is never
/// applied to the changed firmware.
// NOT cancel-safe: component commit reboots the target and changes installed firmware.
pub(super) async fn install(
    request: &ApplyRequest,
    changes: &mut ChangeSet,
    ctx: &RouterCtx,
) -> Result<(), Stop> {
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
            return Err(Stop::Armed(ApplyError::Validation));
        }
        let validated = ctx
            .catalog
            .validate(
                "components install",
                HttpMethod::Post,
                &json!({"component":name}),
            )
            .map_err(|_issues| Stop::Armed(ApplyError::Validation))?;
        commands.push(ValidatedCli::new(
            format!("components install {name}"),
            validated,
        ));
    }
    let validated = ctx
        .catalog
        .validate("components commit", HttpMethod::Post, &json!({}))
        .map_err(|_issues| Stop::Armed(ApplyError::Validation))?;
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
                .map_err(|_error| Stop::Armed(ApplyError::Workflow))?,
        );
    }
    // A refused or lost commit may not have rebooted the router, so its timer is still treated
    // as pending.
    drop(
        changes
            .apply_cli_terminal(TerminalCliChangeRequest::new(
                vec![ValidatedCli::new("components commit".to_owned(), validated)],
                Permission::Destructive,
                json!({"prerequisite":true}),
            ))
            .await
            .map_err(|_error| Stop::Armed(ApplyError::Workflow))?,
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
        let info = changes
            .client()
            .detect()
            .await
            .map_err(|_error| Stop::Rebooted(ApplyError::Unreachable))?;
        if !request
            .options
            .install_components
            .iter()
            .all(|name| info.components.contains(name))
        {
            return Err(Stop::Rebooted(ApplyError::Verification));
        }
        return Err(Stop::Rebooted(ApplyError::ReplanRequired));
    }
    Err(Stop::Rebooted(ApplyError::Unreachable))
}
