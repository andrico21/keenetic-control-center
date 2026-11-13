//! Source checks, acknowledgements, drift detection, and recovery arming.

use alloc::sync::Arc;

use kcc_app::{
    permissions::Permission,
    registry::authorize,
    workflow::{ChangeSet, ReplayOutcome, ReplayPolicy},
};
use kcc_catalog::Catalog;
use kcc_domain::{
    RouterCtx,
    configuration::{SafetyMode, TIMER_RANGE},
};
use kcc_rci::{ConfigKind, RciClient, SecretBytes, auth::Credentials, capabilities::SupportTier};
use secrecy::ExposeSecret as _;

use super::{
    Applier, ApplyError, ApplyReport, ApplyRequest, ApplySource, agreements, agreements::audit,
    bootstrap, command, components, drift, settle::Stop,
};
use crate::source::SourceConfig;

/// Checks all read-only prerequisites before arming the first protected mutation.
///
/// # Errors
/// Returns typed source, firmware, drift, agreement, or workflow failures.
// NOT cancel-safe: cancellation after arming leaves router recovery active.
pub(super) async fn prepare(mut request: ApplyRequest) -> Result<Applier, ApplyError> {
    if !TIMER_RANGE.contains(&request.options.safety_seconds) {
        return Err(ApplyError::Validation);
    }
    authorize(&request.role, Permission::Migrate, &request.target)
        .map_err(|_error| ApplyError::Workflow)?;
    let (workflow, actor, role) = (&request.workflow, request.actor.clone(), &request.role);
    let begun = match request.reservation.take() {
        Some(reservation) => {
            workflow
                .begin_reserved_migration(reservation, actor, role)
                .await
        }
        None => workflow.begin_migration(&request.target, actor, role).await,
    };
    let mut changes = begun.map_err(|_error| ApplyError::Workflow)?;
    let original = changes.client();
    let bytes = source_bytes(&request, &original).await?;
    let source =
        SourceConfig::from_bytes(bytes.expose_secret()).map_err(|_error| ApplyError::Source)?;
    let info = original
        .detect()
        .await
        .map_err(|_error| ApplyError::Unreachable)?;
    match info.support_tier() {
        SupportTier::HardwareVerified => {}
        SupportTier::DocumentationBased if request.options.ack_documentation_tier => {
            audit(&request, "migration.ack_documentation_tier").await?;
        }
        SupportTier::DocumentationBased => return Err(ApplyError::UnverifiedFirmwareTier),
        SupportTier::Unsupported | _ => return Err(ApplyError::Firmware),
    }
    let firmware = source
        .firmware_or(request.options.source_firmware)
        .ok_or(ApplyError::Firmware)?;
    if info.firmware.is_none_or(|target| target < firmware) {
        return Err(ApplyError::Firmware);
    }
    let backup = original
        .download_config(ConfigKind::Startup)
        .await
        .map_err(|_error| ApplyError::Unreachable)?;
    let running = original
        .download_config(ConfigKind::Running)
        .await
        .map_err(|_error| ApplyError::Unreachable)?;
    drift::check(&request, &source, &backup, &running)?;
    if changes.baseline().checksum != request.plan.target_fingerprint.last_change_checksum {
        return Err(ApplyError::Drift);
    }
    let agreements = agreements::pending(&request, &original).await?;
    let catalog = Catalog::for_router(&info).map_err(|_error| ApplyError::Validation)?;
    for line in request
        .plan
        .phases
        .additive
        .iter()
        .chain(&request.plan.phases.prune)
        .chain(&request.plan.phases.management)
    {
        drop(command::build(&catalog, line.expose_command())?);
    }
    validate_credentials(&request, &original).await?;
    let mode = SafetyMode::decide(info.system_mode.as_ref(), changes.baseline())
        .map_err(|_unknown| ApplyError::ModeUnknown)?;
    let ctx = RouterCtx::new(Arc::clone(&original), catalog);
    bootstrap::initialize(&request, &mut changes, &ctx).await?;
    Stop::arm(&mut changes, &ctx, mode, request.options.safety_seconds).await?;
    let prepared = match initialize(&request, &mut changes, agreements).await {
        Ok(()) => components::install(&request, &mut changes, &ctx).await,
        Err(error) => Err(Stop::Armed(error)),
    };
    if let Err(stop) = prepared {
        return Err(stop.settle(&mut changes, &ctx, mode).await);
    }
    let armed_at = request.options.clock.now();
    let credential = request
        .options
        .management_password
        .as_ref()
        .map(|password| Credentials::new(original.credentials().login, password.clone()));
    let report = ApplyReport {
        warnings: request.options.initial_warnings.clone(),
        ..ApplyReport::default()
    };
    Ok(Applier {
        changes,
        plan: request.plan,
        original,
        backup,
        baseline: running,
        mode,
        options: request.options,
        credential,
        armed_at,
        report,
    })
}

/// Requires the replacement credential to match the reviewed primary-password command.
///
/// # Errors
/// Returns missing or mismatched credential input before any write.
async fn validate_credentials(
    request: &ApplyRequest,
    client: &RciClient,
) -> Result<(), ApplyError> {
    use kcc_config::config_text::{Token, flatten, parse};

    let identity = client.credentials();
    if let Some(url) = &request.plan.reconnect_url {
        let endpoint = url.parse().map_err(|_error| ApplyError::Validation)?;
        drop(
            client
                .retarget(endpoint, None)
                .await
                .map_err(|_error| ApplyError::Validation)?,
        );
    }
    for line in &request.plan.phases.management {
        let parsed = parse(line.expose_command()).map_err(|_error| ApplyError::Validation)?;
        for command in flatten(&parsed) {
            if let [
                Token::Word(user),
                Token::Word(login),
                Token::Word(password),
                Token::Word(kind),
                Token::Word(secret),
            ] = command.tokens.as_slice()
                && user == "user"
                && login == &identity.login
                && password == "password"
                && kind == "plain"
            {
                let supplied = request
                    .options
                    .management_password
                    .as_ref()
                    .ok_or(ApplyError::PasswordRequired)?;
                if supplied.expose_secret() != secret {
                    return Err(ApplyError::Validation);
                }
            }
        }
    }
    Ok(())
}

/// Applies confirmed agreements after recovery is armed.
///
/// # Errors
/// Returns audit or protected agreement failures.
// NOT cancel-safe: an agreement can be accepted before its receipt arrives.
async fn initialize(
    request: &ApplyRequest,
    changes: &mut ChangeSet,
    agreements: Vec<&str>,
) -> Result<(), ApplyError> {
    for agreement in agreements {
        audit(request, &format!("migration.confirm_{agreement}")).await?;
        let client = changes.client();
        let catalog = Catalog::for_router(
            &client
                .detect()
                .await
                .map_err(|_error| ApplyError::Workflow)?,
        )
        .map_err(|_error| ApplyError::Validation)?;
        let command = command::build(&catalog, &format!("{agreement} accept"))?;
        let result = changes
            .replay(&[command], ReplayPolicy::StopOnError)
            .await
            .map_err(|_error| ApplyError::Workflow)?;
        if result.outcomes != [ReplayOutcome::Applied] || result.completion.is_err() {
            return Err(ApplyError::Stopped);
        }
    }
    Ok(())
}

/// Loads the chosen source without probing unrelated routers.
///
/// # Errors
/// Returns scope, origin collision, backup, or source-read failures.
// cancel-safe: source acquisition only reads.
async fn source_bytes(
    request: &ApplyRequest,
    target: &RciClient,
) -> Result<SecretBytes, ApplyError> {
    match &request.source {
        ApplySource::LiveRouter { id, client } => {
            authorize(&request.role, Permission::Migrate, id)
                .map_err(|_error| ApplyError::Workflow)?;
            if client.router_url() == target.router_url() {
                return Err(ApplyError::SameRouter);
            }
            client
                .download_config(ConfigKind::Startup)
                .await
                .map_err(|_error| ApplyError::Source)
        }
        ApplySource::File(bytes) => Ok(bytes.clone()),
        ApplySource::Preset {
            bytes,
            source_router,
        } => {
            if let Some(router) = source_router {
                authorize(&request.role, Permission::Migrate, router)
                    .map_err(|_error| ApplyError::Workflow)?;
            }
            Ok(bytes.clone())
        }
        ApplySource::Backup {
            store,
            router,
            name,
        } => {
            authorize(&request.role, Permission::Migrate, router)
                .map_err(|_error| ApplyError::Workflow)?;
            let text = store
                .get(router, name)
                .map_err(|_error| ApplyError::Source)?;
            Ok(SecretBytes::from(text.expose_secret().as_bytes().to_vec()))
        }
    }
}
