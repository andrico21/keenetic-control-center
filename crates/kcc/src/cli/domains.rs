//! Curated domain commands: dispatch and the shared read and change helpers.
//!
//! Every operation runs through the same `kcc-domain` functions the Web UI pages use;
//! changes go through the change workflow as the CLI principal.

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest},
};
use kcc_domain::{ChangeOp, RouterCtx};
use kcc_i18n::{bundle::MessageKey, keys};
use serde::Serialize;
use serde_json::Value;

use super::{
    args_domains::DomainCommand,
    change::{Gate, applied, run as run_change},
    context::{Ctx, Services, Target},
    dom_admin, dom_core, dom_dns, dom_jobs, dom_lan, dom_link, dom_mgmt, dom_net, dom_policies,
    dom_routes, dom_vpn, dom_vpn_server, dom_wire,
    exit::Outcome,
};

/// Runs a domain command.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) async fn run(ctx: &Ctx, command: DomainCommand) -> Outcome {
    match command {
        DomainCommand::System(sub) => dom_core::system(ctx, sub).await,
        DomainCommand::Internet(sub) => dom_core::internet(ctx, sub).await,
        DomainCommand::Diagnostics(sub) => dom_jobs::diagnostics(ctx, sub).await,
        DomainCommand::Clients(sub) => dom_lan::clients(ctx, sub).await,
        DomainCommand::Dhcp(sub) => dom_lan::dhcp(ctx, sub).await,
        DomainCommand::Segments(sub) => dom_lan::segments(ctx, sub).await,
        DomainCommand::RouterUsers(sub) => dom_net::router_users(ctx, sub).await,
        DomainCommand::Routes(sub) => dom_routes::routes(ctx, sub).await,
        DomainCommand::Policies(sub) => dom_policies::policies(ctx, sub).await,
        DomainCommand::Nat(sub) => dom_routes::nat(ctx, sub).await,
        DomainCommand::Firewall(sub) => dom_admin::firewall(ctx, sub).await,
        DomainCommand::Services(sub) => dom_mgmt::services(ctx, sub).await,
        DomainCommand::Components(sub) => dom_jobs::components(ctx, sub).await,
        DomainCommand::Storage(sub) => dom_admin::storage(ctx, sub).await,
        DomainCommand::Schedules(sub) => dom_admin::schedules(ctx, sub).await,
        other @ (DomainCommand::Keendns(_)
        | DomainCommand::Log(_)
        | DomainCommand::Dns(_)
        | DomainCommand::Vpn(_)
        | DomainCommand::VpnServer(_)
        | DomainCommand::Interfaces(_)
        | DomainCommand::Wan(_)
        | DomainCommand::Wifi(_)
        | DomainCommand::Mesh(_)) => run_wire(ctx, other).await,
    }
}

/// Runs the domain commands of `dom_wire`.
///
/// # Errors
///
/// Returns the command's failure with its exit code.
// NOT cancel-safe: changes may apply before cancellation.
async fn run_wire(ctx: &Ctx, command: DomainCommand) -> Outcome {
    match command {
        DomainCommand::Keendns(sub) => dom_mgmt::keendns(ctx, sub).await,
        DomainCommand::Log(sub) => dom_wire::log(ctx, sub).await,
        DomainCommand::Dns(sub) => dom_dns::dns(ctx, sub).await,
        DomainCommand::Vpn(sub) => dom_vpn::vpn(ctx, sub).await,
        DomainCommand::VpnServer(sub) => dom_vpn_server::vpn_server(ctx, sub).await,
        DomainCommand::Interfaces(sub) => dom_link::interfaces(ctx, sub).await,
        DomainCommand::Wan(sub) => dom_link::wan(ctx, sub).await,
        DomainCommand::Wifi(sub) => dom_link::wifi(ctx, sub).await,
        DomainCommand::Mesh(sub) => dom_link::mesh(ctx, sub).await,
        DomainCommand::System(_)
        | DomainCommand::Internet(_)
        | DomainCommand::Diagnostics(_)
        | DomainCommand::Clients(_)
        | DomainCommand::Dhcp(_)
        | DomainCommand::Segments(_)
        | DomainCommand::RouterUsers(_)
        | DomainCommand::Routes(_)
        | DomainCommand::Policies(_)
        | DomainCommand::Nat(_)
        | DomainCommand::Firewall(_)
        | DomainCommand::Services(_)
        | DomainCommand::Components(_)
        | DomainCommand::Storage(_)
        | DomainCommand::Schedules(_) => Ok(()),
    }
}

/// One connected router for one domain command.
#[derive(Debug)]
pub(crate) struct Session<'ctx> {
    /// The invocation.
    ctx: &'ctx Ctx,
    /// Application services.
    services: Services,
    /// The authorized, connected router.
    target: Target,
}

impl<'ctx> Session<'ctx> {
    /// Authorizes `permission` on the router (before any request), then connects.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal or connection failures.
    // cancel-safe: connecting only reads router state.
    pub(crate) async fn open(ctx: &'ctx Ctx, permission: Permission) -> Outcome<Self> {
        let services = ctx.services()?;
        let target = ctx.target(&services, &[permission]).await?;
        Ok(Self {
            ctx,
            services,
            target,
        })
    }

    /// The router's domain context.
    pub(crate) const fn router(&self) -> &RouterCtx {
        self.target.router()
    }

    /// The connected router.
    pub(crate) const fn target(&self) -> &Target {
        &self.target
    }

    /// The login of the router's profile, which account changes must keep.
    ///
    /// # Errors
    ///
    /// Returns registry failures.
    pub(crate) fn profile_login(&self) -> Outcome<String> {
        Ok(self
            .services
            .registry()
            .get(self.target.id())?
            .profile
            .login)
    }

    /// Prints a domain read result.
    ///
    /// # Errors
    ///
    /// Returns serialization or output failures.
    pub(crate) fn show<T>(&self, value: &T) -> Outcome
    where
        T: Serialize,
    {
        let document = serde_json::to_value(value)?;
        let human = match &document {
            Value::String(text) => text.clone(),
            Value::Null
            | Value::Bool(_)
            | Value::Number(_)
            | Value::Array(_)
            | Value::Object(_) => serde_json::to_string_pretty(&document)?,
        };
        self.ctx.out().emit(&document, &human)
    }

    /// Prints rows as a table with localized headers, or `value` with `--json`.
    ///
    /// # Errors
    ///
    /// Returns serialization or output failures.
    pub(crate) fn table<T>(
        &self,
        value: &T,
        headers: &[MessageKey],
        rows: &[Vec<String>],
    ) -> Outcome
    where
        T: Serialize,
    {
        self.ctx
            .out()
            .table(&serde_json::to_value(value)?, headers, rows)
    }

    /// Runs `work` as one change under `gate` and prints the result.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal, a missing confirmation or the workflow failure.
    // NOT cancel-safe: the change may apply before cancellation.
    pub(crate) async fn change<W>(&self, gate: Gate, work: W) -> Outcome
    where
        W: AsyncFnOnce(&mut ChangeSet, &RouterCtx) -> Outcome<Value>,
    {
        let document = run_change(self.ctx, &self.services, &self.target, gate, work).await?;
        let out = self.ctx.out();
        out.emit(&document, &out.tr(keys::CLI_APPLIED, &[]))
    }

    /// Applies a planned operation's CLI request.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal, a missing confirmation or the workflow failure.
    // NOT cancel-safe: the change may apply before cancellation.
    pub(crate) async fn cli(&self, operation: &ChangeOp, request: CliChangeRequest) -> Outcome {
        self.change(Gate::of(operation), async |changes, _router| {
            let result = changes.apply_cli(request).await?;
            Ok(applied(result.unsaved))
        })
        .await
    }
}
