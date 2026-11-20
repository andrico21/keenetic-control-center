//! The policy switch: one registered client under one existing connection policy.
//!
//! The change goes through the leased change workflow (conflict check, automatic backup,
//! read-back, audit), inside the router's fail-safe bracket when the catalog rates it a
//! management change. It is never saved: a router restart undoes it.

extern crate alloc;

use alloc::sync::Arc;

use kcc_app::{
    audit::Actor,
    jobs::JobTarget,
    permissions::Role,
    registry::RouterRegistry,
    workflow::{ChangeSet, ChangeWorkflow},
};
use kcc_catalog::{Catalog, Risk};
use kcc_domain::{
    RouterCtx,
    clients::{self, Client},
    configuration::{SafetyMode, bracket::guarded},
    policies::read::policies,
};

use super::{ActionDeps, ActionResult, Call, failed, failure};

/// What the job needs, owned.
struct Switch {
    /// Router profiles.
    registry: Arc<RouterRegistry>,
    /// The change workflow.
    workflow: Arc<ChangeWorkflow>,
    /// The router.
    router: String,
    /// `system:schedule:<id>`.
    actor: Actor,
    /// The owner's role.
    role: Role,
    /// The client's MAC.
    mac: String,
    /// The policy name.
    policy: String,
}

/// Puts the client `mac` under `policy` on `call`'s router.
// NOT cancel-safe: see `ActionDeps::in_job`.
pub(super) async fn switch(
    deps: &ActionDeps,
    call: &Call<'_>,
    (mac, policy): (&str, &str),
) -> ActionResult {
    let switch = Switch {
        registry: Arc::clone(&deps.registry),
        workflow: Arc::clone(&deps.workflow),
        router: call.schedule.router.clone(),
        actor: call.actor.clone(),
        role: call.role.clone(),
        mac: mac.to_owned(),
        policy: policy.to_owned(),
    };
    let target = JobTarget::Write(switch.router.clone());
    deps.in_job("policy_switch", target, move || run(switch))
        .await
}

/// The job's work, under a bracket guard from the lease to the last read.
// NOT cancel-safe: dropped after the change is sent, it stays unverified and unaudited.
async fn run(switch: Switch) -> ActionResult {
    let _bracket = switch.workflow.brackets().enter();
    let mut changes = match switch
        .workflow
        .begin(&switch.router, switch.actor.clone(), &switch.role, false)
        .await
    {
        Ok(changes) => changes,
        Err(error) => return failure(&error),
    };
    let router = match context(&switch.registry, &switch.router, &changes).await {
        Ok(router) => router,
        Err(result) => return result,
    };
    let client = match checked(&router, &switch).await {
        Ok(client) => client,
        Err(result) => return result,
    };
    let Ok(operation) = clients::plan_policy(
        &router,
        &client,
        &clients::registration_name(&client),
        &switch.policy,
    ) else {
        return failed("plan");
    };
    let applied = if operation.risk == Risk::Management {
        let Ok(mode) = SafetyMode::for_change(&changes) else {
            return failed("router");
        };
        guarded(
            &mut changes,
            &router,
            mode,
            operation.permission,
            || true,
            async |bracketed: &mut ChangeSet, context: &RouterCtx| {
                clients::apply(bracketed, context, &operation)
                    .await
                    .map(|result| (result.unsaved, true))
            },
        )
        .await
        .map_err(|_failure| ())
    } else {
        clients::apply(&mut changes, &router, &operation)
            .await
            .map(|result| result.unsaved)
            .map_err(|_error| ())
    };
    let Ok(unsaved) = applied else {
        return failed("router");
    };
    let checksum = changes
        .current_last_change()
        .await
        .ok()
        .map(|last| last.checksum);
    ActionResult::Done {
        unsaved,
        checksum,
        job: None,
    }
}

/// The router context of `changes`' client with the router's catalog.
///
/// # Errors
///
/// A failed result when the router cannot be detected or has no catalog.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, a read.
async fn context(
    registry: &RouterRegistry,
    router: &str,
    changes: &ChangeSet,
) -> Result<RouterCtx, ActionResult> {
    let info = registry
        .poll_info(router)
        .await
        .map_err(|_error| failed("router"))?;
    let catalog = Catalog::for_router(&info).map_err(|_error| failed("router"))?;
    Ok(RouterCtx::new(changes.client(), catalog))
}

/// The client, when it is registered and the policy exists; nothing is sent otherwise.
///
/// # Errors
///
/// Failed `client_unknown` or `policy_unknown`, or `router` for a failed read.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads.
async fn checked(router: &RouterCtx, switch: &Switch) -> Result<Client, ActionResult> {
    let client = clients::read_client(router, &switch.mac)
        .await
        .map_err(|_error| failed("router"))?
        .filter(|client| client.registered == Some(true))
        .ok_or_else(|| failed("client_unknown"))?;
    let known = policies(router)
        .await
        .map_err(|_error| failed("router"))?
        .iter()
        .any(|state| state.name.as_deref() == Some(switch.policy.as_str()));
    known
        .then_some(client)
        .ok_or_else(|| failed("policy_unknown"))
}
