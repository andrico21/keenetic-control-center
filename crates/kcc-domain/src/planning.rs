//! Catalog validation of planned requests, shared by the domain planners.

use kcc_app::permissions::Permission;
use kcc_catalog::{HttpMethod, Risk, ValidatedRequest};
use serde_json::Value;

use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// `body` validated as a POST of the catalog command `path` on the router's catalog.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] with the catalog's issues when the catalog refuses
/// the request.
pub(crate) fn validate(router: &RouterCtx, path: &str, body: &Value) -> Result<ValidatedRequest> {
    router
        .catalog
        .validate(path, HttpMethod::Post, body)
        .map_err(|issues| DomainError::Validation { issues })
}

/// A plan of the single validated request `path` with `body`, at `risk`, needing `Write`
/// and carrying no verification of its own.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] with the catalog's issues when the catalog refuses
/// the request.
pub(crate) fn plan_one(
    router: &RouterCtx,
    path: &str,
    body: &Value,
    risk: Risk,
) -> Result<ChangeOp> {
    Ok(ChangeOp::new(
        vec![validate(router, path, body)?],
        Vec::new(),
        risk,
        Permission::Write,
        false,
    ))
}
