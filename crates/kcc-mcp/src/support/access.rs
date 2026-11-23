//! Request identity, router authorization, and protected-workflow entry for every tool.

use alloc::sync::Arc;
use core::slice::from_ref;

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::{KCC_ACCOUNT_ROLE, Permission, Role},
    registry::authorize,
    workflow::ChangeSet,
};
use kcc_catalog::{Catalog, Risk};
use kcc_config::mask::mask_reply;
use kcc_domain::RouterCtx;
use rmcp::model::Tool;
use rmcp_server_kit::rbac::{current_identity, current_role};
use serde_json::Value;
use tokio::task;

use super::{
    call::current_request_id,
    errors::map_workflow,
    gates::{McpGates, of_call},
    principal,
};
use crate::{KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers};

#[expect(
    clippy::multiple_inherent_impl,
    reason = "the RMCP `#[tool_router]` macro owns the handler impl block in generic/router.rs, so the remaining inherent methods live here"
)]
impl KccMcp {
    /// Lists tools visible to the caller: those the live gates admit; stdio sessions are
    /// also filtered by the fallback role.
    pub(crate) fn visible_tools(&self, http_identity: bool) -> Vec<Tool> {
        let gates = self.gates_now();
        let mut tools = self.tool_router.list_all();
        tools.retain(|tool| self.admits(&gates, &tool.name));
        if !http_identity {
            tools.retain(|tool| {
                self.tool_specs
                    .iter()
                    .find(|spec| spec.name == tool.name)
                    .is_some_and(|spec| self.fallback_role.grants(spec.permission))
            });
        }
        tools
    }

    /// Makes this handler's `[mcp]` gates the live ones of every handler sharing its
    /// cell: open sessions are bound by them, where stricter than their own, at their
    /// next call.
    #[inline]
    pub fn publish_gates(&self) {
        self.gates.store(Arc::new(McpGates::new(&self.config)));
    }

    /// The gates a call starting now runs under: the stricter of the live gates and
    /// this handler's own settings.
    pub(crate) fn gates_now(&self) -> McpGates {
        self.gates.load().narrowed(&self.config)
    }

    /// The gates of the tool call this task runs, or those of a call starting now.
    pub(crate) fn call_gates(&self) -> Arc<McpGates> {
        of_call().unwrap_or_else(|| Arc::new(self.gates_now()))
    }

    /// Whether `gates` admit the tool `name`; a tool kcc does not define is refused.
    pub(crate) fn admits(&self, gates: &McpGates, name: &str) -> bool {
        self.definitions
            .iter()
            .find(|definition| definition.name == name)
            .is_some_and(|definition| gates.admits(definition))
    }

    /// The tools the caller may list: the visible ones, and for a kcc account token only
    /// those its account's current role grants.
    ///
    /// # Errors
    ///
    /// `forbidden` when a kcc account token's account or grant does not stand.
    pub(crate) fn listed_tools(&self, http_identity: bool) -> Result<Vec<Tool>, McpFailure> {
        let mut tools = self.visible_tools(http_identity);
        if principal::is_kcc_account() {
            let identity = self.identity()?;
            tools.retain(|tool| self.permits(&identity.role, &tool.name));
        }
        Ok(tools)
    }

    /// Whether `role` holds the coarse permission of the tool `name`, the gate the kit's
    /// RBAC applies to every caller but a kcc account token; a tool kcc does not define is
    /// refused.
    pub(crate) fn permits(&self, role: &Role, name: &str) -> bool {
        self.definitions
            .iter()
            .find(|definition| definition.name == name)
            .is_some_and(|definition| role.grants(definition.permission))
    }

    /// Resolves the caller to a configured role, or the stdio fallback role, under its
    /// namespaced name ([`principal::name`]). A kcc account token gets its account's
    /// current role, resolved when the request started.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    pub(crate) fn identity(&self) -> Result<McpIdentity, McpFailure> {
        let role = match current_role() {
            Some(name) if name == KCC_ACCOUNT_ROLE => {
                let current = principal::account_role()
                    .ok_or(McpFailure::Forbidden)?
                    .map_err(|refusal| {
                        tracing::warn!(%refusal, "kcc account token refused");
                        McpFailure::Forbidden
                    })?;
                self.roles.find(&current).ok_or(McpFailure::Forbidden)?
            }
            Some(name) => self.roles.find(&name).ok_or(McpFailure::Forbidden)?,
            None => self
                .roles
                .find(&self.fallback_role.name)
                .ok_or(McpFailure::Forbidden)?,
        };
        Ok(McpIdentity::new(principal::name(), role))
    }

    /// Records the use of the caller's API key, at most once a minute per key; callers
    /// signed in otherwise (a client certificate, stdio) and calls without a recorder
    /// record nothing, so a certificate named like a key never marks that key used.
    // cancel-safe: the state write runs on a blocking thread that completes even if this
    // future is dropped.
    pub(crate) async fn record_key_use(&self) {
        let (Some(recorder), true, Some(key)) =
            (&self.key_use, principal::is_api_key(), current_identity())
        else {
            return;
        };
        let Some(due) = recorder.note(&key) else {
            return;
        };
        match task::spawn_blocking(move || due.persist()).await {
            Ok(Ok(_known)) => {}
            Ok(Err(error)) => tracing::warn!(%error, "API key use could not be recorded"),
            Err(error) => tracing::warn!(%error, "API key use recording task failed"),
        }
    }

    /// Validates `host` and authorizes `permission` on it for the caller.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    pub(crate) fn authorize_host(
        &self,
        permission: Permission,
        host: String,
    ) -> Result<(McpIdentity, RouterId), McpFailure> {
        let router = RouterId::new(host)?;
        let identity = self.identity()?;
        authorize_routers(&identity, permission, from_ref(&router))?;
        Ok((identity, router))
    }

    /// Detects the router and selects its catalog.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    // NOT cancel-safe: it only detects the router and selects its catalog, but it may sign in
    // first, and a sign-in dropped mid-way can leave an orphaned router session.
    pub(crate) async fn catalog(&self, host: &str) -> Result<Catalog, McpFailure> {
        self.audit_alive()?;
        let info = self.registry.poll_info(host).await.map_err(|error| {
            tracing::warn!(host, error = ?error, "MCP router capability detection failed");
            McpFailure::RouterUnreachable
        })?;
        Catalog::for_router(&info).map_err(|error| {
            tracing::warn!(host, error = ?error, "MCP catalog selection failed");
            McpFailure::ValidationFailed
        })
    }

    /// Builds the curated-domain context of an authorized router.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    // NOT cancel-safe: it only detects the router and builds its client, but it may sign in first,
    // and a sign-in dropped mid-way can leave an orphaned router session.
    pub(crate) async fn router_ctx(&self, host: &RouterId) -> Result<RouterCtx, McpFailure> {
        self.audit_alive()?;
        let catalog = self.catalog(host.as_str()).await?;
        let client = self.registry.client(host.as_str()).await.map_err(|error| {
            tracing::warn!(host = host.as_str(), error = ?error, "MCP router client failed");
            McpFailure::RouterUnreachable
        })?;
        Ok(RouterCtx::new(client, catalog))
    }

    /// Opens a protected change set as the MCP actor; its entries carry the call's
    /// request id.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    // NOT cancel-safe: cancellation after lease acquisition releases it through Drop.
    pub(crate) async fn begin_change(
        &self,
        host: &RouterId,
        identity: &McpIdentity,
    ) -> Result<ChangeSet, McpFailure> {
        self.audit_alive()?;
        self.workflow
            .begin(
                host.as_str(),
                Actor::new(ActorKind::Mcp, identity.name.clone()),
                &identity.role,
                false,
            )
            .await
            .map(|changes| changes.with_request_id(current_request_id()))
            .map_err(map_workflow)
    }

    /// Refuses router work when its required audit writer has terminated.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    fn audit_alive(&self) -> Result<(), McpFailure> {
        self.audit.as_ref().map_or(Ok(()), |audit| {
            audit.require_alive().map_err(|_error| McpFailure::Internal)
        })
    }

    /// Refuses a destructive operation while the server-wide switch is off, then one
    /// without confirmation, each with its own reason code.
    ///
    /// # Errors
    ///
    /// Returns an `McpFailure` naming the refusal or failure to report to the client.
    pub(crate) fn require_destructive(&self, risk: Risk, confirm: bool) -> Result<(), McpFailure> {
        if risk != Risk::Destructive {
            return Ok(());
        }
        if !self.call_gates().allow_destructive() {
            return Err(McpFailure::DestructiveDisabled);
        }
        if !confirm {
            return Err(McpFailure::ConfirmRequired);
        }
        Ok(())
    }
}

/// `reply`, a router answer from `host`, as `identity` may see it: as the router sent it
/// with `RevealSecrets` on `host`, otherwise with every secret redacted ([`mask_reply`]).
pub(crate) fn reply_for(identity: &McpIdentity, host: &RouterId, mut reply: Value) -> Value {
    if authorize(&identity.role, Permission::RevealSecrets, host.as_str()).is_err() {
        mask_reply(&mut reply, "<redacted>");
    }
    reply
}
