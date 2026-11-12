//! Request identity, router authorization, and protected-workflow entry for every tool.

use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::Permission,
    workflow::ChangeSet,
};
use kcc_catalog::{Catalog, Risk};
use kcc_domain::RouterCtx;
use rmcp_server_kit::rbac::{current_identity, current_role};

use super::errors::map_workflow;
use crate::{KccMcp, McpFailure, McpIdentity, RouterId, authorize_routers};

impl KccMcp {
    /// Lists tools visible to the caller; stdio sessions are filtered by the fallback role.
    pub(crate) fn visible_tools(&self, http_identity: bool) -> Vec<rmcp::model::Tool> {
        let mut tools = self.tool_router.list_all();
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

    /// Resolves the caller to a configured role, or the stdio fallback role.
    pub(crate) fn identity(&self) -> Result<McpIdentity, McpFailure> {
        let role = match current_role() {
            Some(name) => self.roles.find(&name).ok_or(McpFailure::Forbidden)?,
            None => self
                .roles
                .find(&self.fallback_role.name)
                .ok_or(McpFailure::Forbidden)?,
        };
        Ok(McpIdentity::new(
            current_identity().unwrap_or_else(|| "stdio".to_owned()),
            role,
        ))
    }

    /// Records the use of the caller's API key, at most once a minute per key; stdio
    /// sessions and calls without a recorder record nothing.
    // cancel-safe: the state write runs on a blocking thread that completes even if this
    // future is dropped.
    pub(crate) async fn record_key_use(&self) {
        let (Some(recorder), Some(_role), Some(key)) =
            (&self.key_use, current_role(), current_identity())
        else {
            return;
        };
        let Some(due) = recorder.note(&key) else {
            return;
        };
        match tokio::task::spawn_blocking(move || due.persist()).await {
            Ok(Ok(_known)) => {}
            Ok(Err(error)) => tracing::warn!(%error, "API key use could not be recorded"),
            Err(error) => tracing::warn!(%error, "API key use recording task failed"),
        }
    }

    /// Validates `host` and authorizes `permission` on it for the caller.
    pub(crate) fn authorize_host(
        &self,
        permission: Permission,
        host: String,
    ) -> Result<(McpIdentity, RouterId), McpFailure> {
        let router = RouterId::new(host)?;
        let identity = self.identity()?;
        authorize_routers(&identity, permission, core::slice::from_ref(&router))?;
        Ok((identity, router))
    }

    /// Detects the router and selects its catalog.
    pub(crate) async fn catalog(&self, host: &str) -> Result<Catalog, McpFailure> {
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
    pub(crate) async fn router_ctx(&self, host: &RouterId) -> Result<RouterCtx, McpFailure> {
        let catalog = self.catalog(host.as_str()).await?;
        let client = self.registry.client(host.as_str()).await.map_err(|error| {
            tracing::warn!(host = host.as_str(), error = ?error, "MCP router client failed");
            McpFailure::RouterUnreachable
        })?;
        Ok(RouterCtx::new(client, catalog))
    }

    /// Opens a protected change set as the MCP actor.
    pub(crate) async fn begin_change(
        &self,
        host: &RouterId,
        identity: &McpIdentity,
    ) -> Result<ChangeSet, McpFailure> {
        self.workflow
            .begin(
                host.as_str(),
                Actor::new(ActorKind::Mcp, identity.name.clone()),
                &identity.role,
                None,
                false,
            )
            .await
            .map_err(map_workflow)
    }

    /// Refuses a destructive operation while the server-wide switch is off, then one
    /// without confirmation, each with its own reason code.
    pub(crate) fn require_destructive(&self, risk: Risk, confirm: bool) -> Result<(), McpFailure> {
        if risk != Risk::Destructive {
            return Ok(());
        }
        if !self.config.allow_destructive {
            return Err(McpFailure::DestructiveDisabled);
        }
        if !confirm {
            return Err(McpFailure::ConfirmRequired);
        }
        Ok(())
    }
}
