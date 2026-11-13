//! Running a change through the change workflow as the CLI principal.
//!
//! Every change runs in a leased change set (permission and scope, one pre-change backup
//! per window, the conflict check, read-back, audit with `actor=cli:<user>`). A
//! management change also runs inside the router's fail-safe timer, armed before and
//! disarmed after it while the router still answers. An attempt that fails after the
//! confirmation leaves a `cli.change` audit entry with outcome `failed` and the error
//! kind.

use kcc_app::{permissions::Permission, workflow::ChangeSet};
use kcc_catalog::Risk;
use kcc_domain::{
    ChangeOp, RouterCtx,
    configuration::{
        SafetyMode, SafetyNet, bracket::guarded, read_last_change, workflow_last_change,
    },
};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::{Value, json};

use super::{
    context::{Ctx, Services, Target},
    exit::{Failure, Outcome},
    secret::confirm,
};

/// Who arms the recovery timer around a change.
#[derive(Debug, Clone, Copy)]
enum Timer {
    /// Nobody: the change needs no timer.
    Off,
    /// The runner arms it around the work.
    Runner,
}

/// What one change needs: its risk and permission, and whether a write asks first.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gate {
    /// Operation risk.
    risk: Risk,
    /// Permission the operation itself needs.
    permission: Permission,
    /// Raw commands ask before an ordinary write too.
    ask_on_write: bool,
    /// Who arms the recovery timer around a management change.
    timer: Timer,
    /// The router persists the change at once: labelled before it runs.
    persists: bool,
    /// What the command did when it leaves no change waiting for a save, such as a restart;
    /// `None` for an ordinary change.
    outcome: Option<MessageKey>,
}

impl Timer {
    /// The runner's timer when `management`, else none.
    const fn around(management: bool) -> Self {
        if management { Self::Runner } else { Self::Off }
    }
}

impl Gate {
    /// The gate of a planned domain operation.
    pub(crate) fn of(operation: &ChangeOp) -> Self {
        Self {
            risk: operation.risk,
            permission: operation.permission,
            ask_on_write: false,
            timer: Timer::around(operation.risk == Risk::Management),
            persists: operation.persists(),
            outcome: None,
        }
    }

    /// A gate from its parts.
    pub(crate) const fn new(risk: Risk, permission: Permission, ask_on_write: bool) -> Self {
        Self {
            risk,
            permission,
            ask_on_write,
            timer: Timer::around(matches!(risk, Risk::Management)),
            persists: false,
            outcome: None,
        }
    }

    /// The same gate for a command whose headline is `outcome`, not an applied change.
    pub(crate) const fn reporting(self, outcome: MessageKey) -> Self {
        Self {
            outcome: Some(outcome),
            ..self
        }
    }

    /// The same gate for a change the router persists at once when `persists`.
    pub(crate) const fn persisting(self, persists: bool) -> Self {
        Self { persists, ..self }
    }

    /// Preserves a raw request's management requirement independently of maximum risk.
    pub(crate) const fn recovery(self, management: bool) -> Self {
        Self {
            timer: Timer::around(management),
            ..self
        }
    }

    /// The headline of the finished command: its stated outcome, else the applied change,
    /// stored by the router already or waiting for a save.
    pub(crate) const fn applied(self) -> MessageKey {
        match self.outcome {
            Some(outcome) => outcome,
            None if self.persists => keys::CLI_APPLIED_PERSISTED,
            None => keys::CLI_APPLIED,
        }
    }

    /// The permissions held for this change: what [`SafetyNet::required`] asks of it.
    fn permissions(self) -> Vec<Permission> {
        SafetyNet::required(self.permission, self.risk)
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
    run_completed(ctx, services, target, gate, async |changes, router| {
        work(changes, router).await.map(|value| (value, true))
    })
    .await
}

/// Runs work whose completion explicitly records whether any change applied.
///
/// # Errors
/// Returns authorization, work or recovery cleanup failures.
// NOT cancel-safe: cancellation may leave a change applied or recovery armed.
pub(crate) async fn run_completed<W>(
    ctx: &Ctx,
    services: &Services,
    target: &Target,
    gate: Gate,
    work: W,
) -> Outcome<Value>
where
    W: AsyncFnOnce(&mut ChangeSet, &RouterCtx) -> Outcome<(Value, bool)>,
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
    if gate.persists {
        ctx.out()
            .note(&ctx.out().tr(keys::CLI_PERSISTS_IMMEDIATELY, &[]));
    }
    confirm(
        ctx.out(),
        ctx.globals(),
        gate.risk,
        target.id(),
        gate.ask_on_write,
    )?;
    let attempt = async move {
        let mut changes = services
            .workflow()
            .begin(target.id(), ctx.principal().actor(), &role, None, false)
            .await?;
        match gate.timer {
            Timer::Off => {
                return work(&mut changes, target.router())
                    .await
                    .map(|(document, _applied)| labelled(document, gate.persists));
            }
            Timer::Runner => {}
        }
        let mode = SafetyMode::for_change(&changes)?;
        guarded(
            &mut changes,
            target.router(),
            mode,
            gate.permission,
            || true,
            async |bracketed, router| {
                work(bracketed, router)
                    .await
                    .map(|(document, applied)| (labelled(document, gate.persists), applied))
            },
        )
        .await
        .map_err(Failure::recovery)
    }
    .await;
    if let Err(failure) = &attempt {
        let mut params = json!({ "error": failure.exit().name() });
        if failure.fail_safe_armed()
            && let Value::Object(object) = &mut params
        {
            drop(object.insert("fail_safe_armed".to_owned(), json!(true)));
        }
        ctx.audit(services, "cli.change", Some(target.id()), params, "failed")
            .await;
    }
    attempt
}

/// `document` with its `persists_immediately` flag when it is an object; a change the
/// router persisted at once is not `unsaved`.
pub(crate) fn labelled(mut document: Value, persists: bool) -> Value {
    if let Value::Object(object) = &mut document {
        drop(object.insert("persists_immediately".to_owned(), Value::Bool(persists)));
        if persists && let Some(unsaved) = object.get_mut("unsaved") {
            *unsaved = Value::Bool(false);
        }
    }
    document
}

/// The result document of an applied change.
pub(crate) fn applied(unsaved: bool) -> Value {
    json!({ "applied": true, "unsaved": unsaved })
}

/// The router's recovery mechanism, decided before a change set exists from the target's
/// fresh detection and its current `show last-change`.
///
/// # Errors
///
/// Returns the policy refusal when the mode is unknown, or the router read failure.
// cancel-safe: a single read.
pub(crate) async fn recovery_mode(target: &Target) -> Outcome<SafetyMode> {
    let state = read_last_change(target.router()).await?;
    let baseline = workflow_last_change(&state)?;
    Ok(SafetyMode::decide(
        target.info().system_mode.as_ref(),
        &baseline,
    )?)
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_app::permissions::Permission;
    use kcc_catalog::Risk;
    use kcc_i18n::keys;
    use serde_json::Value;

    use super::{Gate, applied, labelled};

    #[test]
    fn a_persisted_change_is_neither_unsaved_nor_headlined_so() {
        let gate = Gate::new(Risk::Write, Permission::RawRci, true);
        for (persists, unsaved, headline) in [
            (true, false, keys::CLI_APPLIED_PERSISTED),
            (false, true, keys::CLI_APPLIED),
        ] {
            let document = labelled(applied(true), persists);
            assert_eq!(
                document.get("unsaved"),
                Some(&Value::Bool(unsaved)),
                "{document}"
            );
            assert_eq!(gate.persisting(persists).applied(), headline);
        }
    }
}
