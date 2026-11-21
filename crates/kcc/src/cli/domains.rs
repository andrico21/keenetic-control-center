//! Curated domain commands: dispatch and the shared read and change helpers.
//!
//! Every operation runs through the same `kcc-domain` functions the Web UI pages use;
//! changes go through the change workflow as the CLI principal.

use kcc_app::{
    permissions::Permission,
    workflow::{ChangeSet, CliChangeRequest},
};
use kcc_domain::{ChangeOp, RouterCtx, router_users::protection::OwnLogins, verification};
use kcc_i18n::bundle::MessageKey;
use serde::Serialize;
use serde_json::Value;

use super::{
    args_domains::DomainCommand,
    change::{Gate, applied, run_headlined},
    context::{Ctx, Services, Target},
    dom_admin, dom_clients, dom_core, dom_dns, dom_jobs, dom_lan, dom_link, dom_mgmt, dom_net,
    dom_policies, dom_routes, dom_vpn, dom_vpn_server, dom_wifi, dom_wire,
    entry::Boxed,
    exit::Outcome,
};

/// Runs a domain command.
///
/// The returned future fails with the command's failure and its exit code; see [`Boxed`]
/// for why it is boxed.
// NOT cancel-safe: changes may apply before cancellation.
pub(crate) fn run(ctx: &Ctx, command: DomainCommand) -> Boxed<'_> {
    match command {
        DomainCommand::System(sub) => Box::pin(dom_core::system(ctx, sub)),
        DomainCommand::Internet(sub) => Box::pin(dom_core::internet(ctx, sub)),
        DomainCommand::Diagnostics(sub) => Box::pin(dom_jobs::diagnostics(ctx, sub)),
        DomainCommand::Clients(sub) => Box::pin(dom_clients::clients(ctx, sub)),
        DomainCommand::Dhcp(sub) => Box::pin(dom_lan::dhcp(ctx, sub)),
        DomainCommand::Segments(sub) => Box::pin(dom_lan::segments(ctx, sub)),
        DomainCommand::RouterUsers(sub) => Box::pin(dom_net::router_users(ctx, sub)),
        DomainCommand::Routes(sub) => Box::pin(dom_routes::routes(ctx, sub)),
        DomainCommand::Policies(sub) => Box::pin(dom_policies::policies(ctx, sub)),
        DomainCommand::Nat(sub) => Box::pin(dom_routes::nat(ctx, sub)),
        DomainCommand::Firewall(sub) => Box::pin(dom_admin::firewall(ctx, sub)),
        DomainCommand::Services(sub) => Box::pin(dom_mgmt::services(ctx, sub)),
        DomainCommand::Components(sub) => Box::pin(dom_jobs::components(ctx, sub)),
        DomainCommand::Storage(sub) => Box::pin(dom_net::storage(ctx, sub)),
        DomainCommand::Schedules(sub) => Box::pin(dom_admin::schedules(ctx, sub)),
        DomainCommand::Keendns(sub) => Box::pin(dom_mgmt::keendns(ctx, sub)),
        DomainCommand::Log(sub) => Box::pin(dom_wire::log(ctx, sub)),
        DomainCommand::Dns(sub) => Box::pin(dom_dns::dns(ctx, sub)),
        DomainCommand::Vpn(sub) => Box::pin(dom_vpn::vpn(ctx, sub)),
        DomainCommand::VpnServer(sub) => Box::pin(dom_vpn_server::vpn_server(ctx, sub)),
        DomainCommand::Interfaces(sub) => Box::pin(dom_link::interfaces(ctx, sub)),
        DomainCommand::Wan(sub) => Box::pin(dom_link::wan(ctx, sub)),
        DomainCommand::Wifi(sub) => Box::pin(dom_wifi::wifi(ctx, sub)),
        DomainCommand::Mesh(sub) => Box::pin(dom_link::mesh(ctx, sub)),
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
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, connecting only reads router state.
    pub(crate) async fn open(ctx: &'ctx Ctx, permission: Permission) -> Outcome<Self> {
        Self::open_permissions(ctx, &[permission]).await
    }

    /// Authorizes every required permission before router discovery.
    ///
    /// # Errors
    /// Returns policy or connection failures.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, connecting only reads router state.
    pub(crate) async fn open_permissions(
        ctx: &'ctx Ctx,
        permissions: &[Permission],
    ) -> Outcome<Self> {
        let services = ctx.services().await?;
        let target = ctx.target(&services, permissions).await?;
        Ok(Self {
            ctx,
            services,
            target,
        })
    }

    /// Refuses a change of an account kcc signs in with before connecting.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal, registry failure, or connection failure.
    // NOT cancel-safe: opening the services may append a migration audit event after the future is
    // dropped.
    pub(crate) async fn open_for_account(
        ctx: &'ctx Ctx,
        permission: Permission,
        account: &str,
    ) -> Outcome<Self> {
        let services = ctx.services().await?;
        let id = ctx.router_id(&services)?;
        let profile = services.registry().get(&id)?.profile;
        OwnLogins::new(&profile.login, profile.read_login.as_deref())?.guard(account)?;
        let target = ctx.target_named(&services, id, &[permission]).await?;
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

    /// The application services the session opened.
    pub(crate) const fn services(&self) -> &Services {
        &self.services
    }

    /// The router accounts kcc signs in with, which account changes must keep.
    ///
    /// # Errors
    ///
    /// Returns registry failures, and the protected-account refusal when the profile
    /// names no login.
    pub(crate) fn profile_login(&self) -> Outcome<OwnLogins> {
        let profile = self.services.registry().get(self.target.id())?.profile;
        Ok(OwnLogins::new(
            &profile.login,
            profile.read_login.as_deref(),
        )?)
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
        let (document, headline) =
            run_headlined(self.ctx, &self.services, &self.target, gate, work).await?;
        let out = self.ctx.out();
        out.emit(&document, &out.tr(headline, &[]))
    }

    /// Applies a planned operation's CLI request.
    ///
    /// # Errors
    ///
    /// Returns the policy refusal, a missing confirmation or the workflow failure.
    // NOT cancel-safe: the change may apply before cancellation.
    pub(crate) async fn cli(&self, operation: &ChangeOp, request: CliChangeRequest) -> Outcome {
        let verified_request = verification::complete(request)?;
        verification::require(&verified_request)?;
        self.change(Gate::of(operation), async |changes, _router| {
            let result = changes.apply_cli(verified_request).await?;
            Ok(applied(result.unsaved))
        })
        .await
    }
}
