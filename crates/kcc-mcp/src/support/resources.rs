//! The router snapshot and catalog resources, read as the caller of the request.

use kcc_app::{
    permissions::Permission,
    registry::{RegistryError, authorize},
};
use rmcp::{
    ErrorData,
    model::{
        ListResourcesResult, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult,
        Resource, ResourceContents,
    },
};
use serde_json::json;

use super::{
    audit,
    call::next_request_id,
    errors::{failure_error, internal_error},
    names,
    shape::{FailureContext, shape},
    truncate::Shaping,
    validate::{MAX_PATH_CHARS, valid_host, valid_text},
};
use crate::{KccMcp, McpFailure, generic::rci::catalog_for_version};

#[expect(
    clippy::multiple_inherent_impl,
    reason = "the RMCP `#[tool_router]` macro owns the handler impl block in generic/router.rs, so the remaining inherent methods live here"
)]
impl KccMcp {
    /// The snapshot resources of the routers the caller may read.
    ///
    /// # Errors
    ///
    /// `forbidden` for a refused caller, `internal` when the registry cannot be read.
    pub(crate) fn resources_list(&self) -> Result<ListResourcesResult, ErrorData> {
        let identity = self.identity().map_err(failure_error)?;
        let resources = self
            .registry
            .list()
            .map_err(|error| internal_error("resources/list", &error))?
            .into_iter()
            .filter(|entry| authorize(&identity.role, Permission::Read, &entry.profile.id).is_ok())
            .map(|entry| {
                Resource::new(
                    format!("kcc://router/{}/snapshot", entry.profile.id),
                    format!("{} snapshot", entry.profile.id),
                )
                .with_mime_type("application/json")
            })
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    /// Reads a router snapshot or a catalog resource as the caller; a refused snapshot
    /// read is audited.
    ///
    /// # Errors
    ///
    /// The MCP error of a refused caller, an invalid or unknown resource, or an
    /// unreachable router.
    // NOT cancel-safe: a refused read queues an audit entry that may be written after the
    // future is dropped; the snapshot wait itself only reads.
    pub(crate) async fn resource_read(
        &self,
        request: ReadResourceRequestParams,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let identity = self.identity().map_err(failure_error)?;
        let uri = request.uri;
        if let Some(host) = uri
            .strip_prefix("kcc://router/")
            .and_then(|rest| rest.strip_suffix("/snapshot"))
        {
            valid_host(host).map_err(failure_error)?;
            if authorize(&identity.role, Permission::Read, host).is_err() {
                let failure = FailureContext::new("resources_read", true, Some(host));
                let request_id = next_request_id();
                audit::failure(self, failure, &McpFailure::Forbidden, &request_id).await;
                return Err(failure_error(McpFailure::Forbidden));
            }
            match self.registry.get(host) {
                Ok(_entry) => {}
                Err(RegistryError::NotFound { id: _ }) => {
                    return Err(failure_error(McpFailure::RouterUnreachable));
                }
                Err(error) => return Err(internal_error("resources/read", &error)),
            }
            let mut receiver = self.poller.subscribe(host).await;
            if receiver.borrow().is_none() && receiver.changed().await.is_err() {
                return Err(failure_error(McpFailure::RouterUnreachable));
            }
            let result = receiver
                .borrow()
                .clone()
                .ok_or_else(|| failure_error(McpFailure::RouterUnreachable))?
                .map_err(|error| {
                    tracing::warn!(host, %error, "MCP snapshot poll failed");
                    failure_error(McpFailure::RouterUnreachable)
                })?;
            let value = json!({
                "host": host,
                "system": result.system,
                "internet": result.internet,
                "interfaces": result.interfaces_summary,
                "clients_count": result.clients_count,
                "wifi": result.wifi_summary,
                "last_change": result.last_change,
                "fetched_at": result.fetched_at
            });
            let text = shape(self, value, Shaping::new(None)).map_err(failure_error)?;
            return Ok(ReadResourceResult::new(vec![
                ResourceContents::text(text, uri).with_mime_type("application/json"),
            ])
            .into());
        }
        if let Some(rest) = uri.strip_prefix("kcc://catalog/") {
            let (version, path) = rest
                .split_once('/')
                .ok_or_else(|| failure_error(McpFailure::InvalidArguments))?;
            let catalog = catalog_for_version(version).map_err(failure_error)?;
            let decoded = path.replace("%20", " ");
            valid_text(&decoded, MAX_PATH_CHARS).map_err(failure_error)?;
            let command = catalog
                .lookup(&decoded)
                .ok_or_else(|| failure_error(McpFailure::InvalidArguments))?;
            let value = json!({
                "version": version,
                "path": command.path,
                "kind": names::command_kind(command.kind),
                "prefix_no": command.prefix_no,
                "schema": catalog.to_json_schema(&decoded)
            });
            let text = shape(self, value, Shaping::new(None)).map_err(failure_error)?;
            return Ok(ReadResourceResult::new(vec![
                ResourceContents::text(text, uri).with_mime_type("application/json"),
            ])
            .into());
        }
        Err(failure_error(McpFailure::InvalidArguments))
    }
}
