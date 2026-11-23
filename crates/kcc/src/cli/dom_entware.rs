//! Entware commands: status, the `opkg` settings and the removal; the setup job lives in
//! `dom_entware_setup`.

use kcc_app::permissions::Permission;
use kcc_domain::{
    entware::{
        self,
        models::{EntwarePlan, EntwareWarning, TimezoneSetting},
    },
    verification,
};
use kcc_i18n::{bundle::MessageKey, keys};
use serde_json::Value;

use super::{
    args_dom_entware::{EntwareCommand, EntwareSetting},
    change::{Gate, applied},
    context::Ctx,
    dom_entware_setup, dom_entware_ssh, dom_entware_ssh_packages, dom_entware_ssh_services,
    domains::Session,
    entry::Boxed,
    exit::Outcome,
};

/// Runs an `entware` command.
///
/// The returned future fails with the command's failure and its exit code; see [`Boxed`]
/// for why it is boxed.
// NOT cancel-safe: changes, and the setup job, may run on after cancellation.
pub(crate) fn entware(ctx: &Ctx, command: EntwareCommand) -> Boxed<'_> {
    match command {
        EntwareCommand::Status => Box::pin(status(ctx)),
        EntwareCommand::Setup { drive, arch } => {
            Box::pin(dom_entware_setup::setup(ctx, drive, arch))
        }
        EntwareCommand::Set(setting) => Box::pin(set(ctx, setting)),
        EntwareCommand::Remove => Box::pin(remove(ctx)),
        EntwareCommand::Ssh(sub) => dom_entware_ssh::ssh(ctx, sub),
        EntwareCommand::Packages(sub) => dom_entware_ssh_packages::packages(ctx, sub),
        EntwareCommand::Services(sub) => dom_entware_ssh_services::services(ctx, sub),
    }
}

/// Prints the Entware status.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
// router session. Apart from that, reads only.
async fn status(ctx: &Ctx) -> Outcome {
    let session = Session::open(ctx, Permission::Read).await?;
    session.show(&entware::read_status(session.router()).await?)
}

/// Changes one Entware setting.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the change may apply before cancellation.
async fn set(ctx: &Ctx, setting: EntwareSetting) -> Outcome {
    let permission = match setting {
        EntwareSetting::Initrc { path: _ } => Permission::Destructive,
        EntwareSetting::Chroot { state: _ }
        | EntwareSetting::Timezone { value: _ }
        | EntwareSetting::DnsOverride { state: _ } => Permission::Write,
    };
    let session = Session::open(ctx, permission).await?;
    let (router, target) = (session.router(), session.target());
    let (id, role) = (target.id(), target.role());
    let plan = match setting {
        EntwareSetting::Chroot { state } => {
            entware::plan_chroot(router, id, role, state.enabled())?
        }
        EntwareSetting::Timezone { value } => {
            let timezone = if value == "auto" {
                TimezoneSetting::Auto
            } else {
                TimezoneSetting::Named(value)
            };
            entware::plan_timezone(router, id, role, timezone)?
        }
        EntwareSetting::Initrc { path } => entware::plan_initrc(router, id, role, &path, true)?,
        EntwareSetting::DnsOverride { state } => {
            entware::plan_dns_override(router, id, role, state.enabled())?
        }
    };
    apply(ctx, &session, plan).await
}

/// Stops running Entware from its drive.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: the change may apply before cancellation.
async fn remove(ctx: &Ctx) -> Outcome {
    let session = Session::open(ctx, Permission::Destructive).await?;
    let target = session.target();
    let plan = entware::plan_remove(session.router(), target.id(), target.role(), true)?;
    apply(ctx, &session, plan).await
}

/// Prints `plan`'s warnings, then applies it under its gate: a destructive line asks for
/// the router id, a management line for `--yes` and runs inside the fail-safe bracket.
///
/// # Errors
///
/// Returns the policy refusal, a missing confirmation or the workflow failure.
// NOT cancel-safe: the change may apply before cancellation.
async fn apply(ctx: &Ctx, session: &Session<'_>, plan: EntwarePlan) -> Outcome {
    let request = verification::complete(entware::change_request(&plan.operation)?)?;
    let out = ctx.out();
    for warning in &plan.warnings {
        out.note(&out.tr(warning_key(*warning), &[]));
    }
    let warnings = serde_json::to_value(&plan.warnings)?;
    session
        .change(Gate::of(&plan.operation), async |changes, _router| {
            let result = changes.apply_cli(request).await?;
            let mut document = applied(result.unsaved);
            if let Value::Object(object) = &mut document {
                drop(object.insert("warnings".to_owned(), warnings));
            }
            Ok(document)
        })
        .await
}

/// The localized text of `warning`.
const fn warning_key(warning: EntwareWarning) -> MessageKey {
    match warning {
        EntwareWarning::ChrootStopsSshManagement => keys::CLI_ENTWARE_WARNING_CHROOT,
        EntwareWarning::DnsOverrideStopsRouterDns | _ => keys::CLI_ENTWARE_WARNING_DNS_OVERRIDE,
    }
}
