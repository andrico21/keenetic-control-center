//! The revoke step: kcc's line removed over a key-only session, then the local state.

use kcc_app::entware_ssh::state::forget;
use kcc_ssh::{
    command::EntwareCommand,
    keys::{Auth, HostKeyPin},
    transport::PinnedTarget,
};

use super::{Flow, install::succeeded};
use crate::{
    RouterCtx,
    entware::{
        self,
        ssh::{error::EntwareError, preflight},
    },
};

/// Removes kcc's line over a key-only session, then forgets the local state; any SSH
/// failure keeps the local state.
///
/// # Errors
/// As [`super::revoke`].
// NOT cancel-safe: dropped after the removal, the line is gone but the record stays; a new
// revoke or a disable finishes.
pub(super) async fn run(flow: &mut Flow<'_>, router: &RouterCtx) -> Result<(), EntwareError> {
    let (services, caller) = (flow.services, flow.caller);
    preflight::authorize_enrolment(caller)?;
    let _lease = services
        .workflow
        .reserve(caller.router, caller.actor, caller.role)?;
    if entware::read_settings(router)
        .await
        .map_err(EntwareError::RevokeUnreachable)?
        .chroot
    {
        return Err(EntwareError::ChrootEnabled);
    }
    let record =
        preflight::checked_record(services, router, caller)?.ok_or(EntwareError::NotEnrolled)?;
    flow.facts.port = Some(record.port);
    flow.facts.fingerprint.clone_from(&record.fingerprint);
    let pinned = record
        .host_key
        .as_deref()
        .ok_or(EntwareError::NotEnrolled)?;
    let pin = HostKeyPin::from_openssh(pinned)?;
    let key = services
        .store
        .load_key(caller.router)?
        .ok_or(EntwareError::NotEnrolled)?;
    let router_id = preflight::router_id(caller)?;
    let removal = async {
        let addresses = preflight::admit(services, router, record.port).await?;
        let session = services
            .pool
            .acquire(&router_id)
            .await?
            .connect(
                PinnedTarget::new(addresses, pin),
                Auth::Key(key),
                services.timeouts,
            )
            .await?;
        succeeded(
            &session
                .run(&EntwareCommand::RemoveKey {
                    router_id: router_id.clone(),
                })
                .await?,
        )
    };
    removal.await.map_err(EntwareError::RevokeFailed)?;
    forget(services.workflow.state(), caller.router)?;
    Ok(())
}
