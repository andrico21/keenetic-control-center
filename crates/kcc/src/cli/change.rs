//! Running a change through the change workflow as the CLI principal.
//!
//! Every change runs in a leased change set (permission and scope, one pre-change backup
//! per window, the conflict check, read-back, audit with `actor=cli:<user>`). A
//! management change also runs inside the router's fail-safe timer, armed before and
//! disarmed after it while the router still answers.

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, WorkflowError},
};
use kcc_catalog::Risk;
use kcc_domain::{
    ChangeOp, RouterCtx,
    configuration::{SafetyMode, SafetyNet},
};
use kcc_i18n::keys;
use kcc_rci::{
    RciError,
    capabilities::{RouterInfo, SystemMode},
};
use serde_json::{Value, json};

use super::{
    context::{Ctx, MANAGEMENT_TIMER, Services, Target},
    exit::{Failure, Outcome},
    secret::confirm,
};

/// What one change needs: its risk and permission, and whether a write asks first.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gate {
    /// Operation risk.
    risk: Risk,
    /// Permission the operation itself needs.
    permission: Permission,
    /// Raw commands ask before an ordinary write too.
    ask_on_write: bool,
    /// The runner arms the fail-safe timer around a management change; `false` when
    /// the domain operation brackets itself.
    timer: bool,
}

impl Gate {
    /// The gate of a planned domain operation.
    pub(crate) const fn of(operation: &ChangeOp) -> Self {
        Self {
            risk: operation.risk,
            permission: operation.permission,
            ask_on_write: false,
            timer: true,
        }
    }

    /// A gate from its parts.
    pub(crate) const fn new(risk: Risk, permission: Permission, ask_on_write: bool) -> Self {
        Self {
            risk,
            permission,
            ask_on_write,
            timer: true,
        }
    }

    /// The same gate for an operation that arms its own fail-safe timer.
    pub(crate) const fn self_bracketed(self) -> Self {
        Self {
            timer: false,
            ..self
        }
    }

    /// The permissions held for this change: its own, and `Destructive` from management
    /// risk up, because a management change runs inside the fail-safe timer.
    fn permissions(self) -> Vec<Permission> {
        let mut needed = vec![self.permission];
        if self.risk >= Risk::Management && self.permission != Permission::Destructive {
            needed.push(Permission::Destructive);
        }
        needed
    }
}

/// Checks `gate`, confirms, and runs `work` in a leased change set on `target`.
///
/// # Errors
///
/// Returns the policy refusal, a missing confirmation, or the workflow failure.
// NOT cancel-safe: a dropped future may leave an applied change or an armed timer; the
// router's own fail-safe timer is the recovery for the latter.
pub(crate) async fn run<W>(
    ctx: &Ctx,
    services: &Services,
    target: &Target,
    gate: Gate,
    work: W,
) -> Outcome<Value>
where
    W: AsyncFnOnce(&mut ChangeSet, &RouterCtx) -> Outcome<Value>,
{
    let role = match ctx
        .principal()
        .authorize(&gate.permissions(), &[target.id()])
    {
        Ok(role) => role,
        Err(failure) => {
            ctx.audit(
                services,
                "cli.refused",
                Some(target.id()),
                Value::Null,
                "forbidden",
            )
            .await;
            return Err(failure);
        }
    };
    confirm(
        ctx.out(),
        ctx.globals(),
        gate.risk,
        target.id(),
        gate.ask_on_write,
    )?;
    let mut changes = services
        .workflow()
        .begin(target.id(), ctx.principal().actor(), &role, None, false)
        .await?;
    if gate.risk != Risk::Management || !gate.timer {
        return work(&mut changes, target.router()).await;
    }
    let mode = safety_mode(target.info());
    drop(
        SafetyNet::arm(
            &mut changes,
            target.router(),
            mode,
            MANAGEMENT_TIMER.as_secs(),
        )
        .await?,
    );
    let applied = work(&mut changes, target.router()).await;
    match SafetyNet::disarm(&mut changes, target.router(), mode).await {
        Ok(_disarmed) => applied,
        Err(WorkflowError::Rci(RciError::Transport | RciError::Timeout)) => {
            ctx.out().note(&ctx.out().tr(keys::CLI_FAILSAFE_LEFT, &[]));
            applied
        }
        Err(error) => applied.and_then(|_value| Err(Failure::from(error))),
    }
}

/// The result document of an applied change.
pub(crate) fn applied(unsaved: bool) -> Value {
    json!({ "applied": true, "unsaved": unsaved })
}

/// The router's recovery mechanism: the fail-safe timer in router mode, else a
/// scheduled reboot.
pub(crate) const fn safety_mode(info: &RouterInfo) -> SafetyMode {
    match info.system_mode {
        Some(SystemMode::Router) => SafetyMode::Router,
        Some(_) | None => SafetyMode::ScheduledReboot,
    }
}
