//! Validation of persisted segment identifiers and deletion ownership.

use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec, WorkflowError,
        refusal::Refusal,
    },
};
use kcc_catalog::HttpMethod;
use kcc_config::{config_text::Ast, quoting::quote_cli_text};
use serde_json::json;

use super::{
    SegmentSpec,
    discovery::{SegmentView, VlanId},
    step,
};
use crate::{DomainError, Result, RouterCtx, config_tree};

/// Writes the ownership marker after the VLAN exists.
///
/// # Errors
///
/// Returns an error when the catalog refuses a request
/// ([`WorkflowError::CatalogValidation`]), or when the change workflow fails: dispatch,
/// read-back or audit (a [`WorkflowError`]).
// NOT cancel-safe: the description may be written before the workflow returns.
pub(super) async fn persist(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    id: u16,
    marker: &str,
) -> CoreResult<(), WorkflowError> {
    let request = router
        .catalog
        .validate(
            "interface description",
            HttpMethod::Post,
            &json!({"description":marker}),
        )
        .map_err(|issues| WorkflowError::CatalogValidation { issues })?;
    let quoted = quote_cli_text(marker).map_err(|_error| Refusal::InvalidInput)?;
    drop(
        changes
            .apply_cli(CliChangeRequest::new(
                vec![ValidatedCli::new(
                    format!("interface Vlan{id} description {quoted}"),
                    request,
                )?],
                vec![VerificationSpec::new(
                    vec!["show".to_owned(), "rc".to_owned()],
                    format!("/interface/Vlan{id}/description"),
                    json!(marker),
                )],
                Permission::Write,
                json!({"operation":"segment_ownership","id":id}),
            ))
            .await?,
    );
    Ok(())
}

/// Parses identifiers before they can become CLI tokens, including persisted records.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]).
pub(super) fn validate(spec: &SegmentSpec) -> Result<()> {
    let _vlan = VlanId::new(spec.vlan_id)?;
    for name in spec
        .switch_ports
        .iter()
        .chain(&spec.access_point)
        .chain(&spec.connection_policy)
    {
        if name.is_empty()
            || name.len() > 128
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'/' | b'.')
            })
        {
            return Err(DomainError::InvalidCliToken);
        }
    }
    Ok(())
}

/// Refuses shared leaves already present before creation rather than claiming ownership.
///
/// # Errors
///
/// Returns an error when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
pub(super) fn check_baseline(spec: &SegmentSpec, tree: &Ast) -> Result<()> {
    let bridge = format!("Bridge{}", spec.id);
    if config_tree::context_has_child(tree, &format!("ip nat {bridge}"), None)
        || config_tree::context_has_child(tree, &format!("ip hotspot policy {bridge} permit"), None)
        || spec.switch_ports.iter().any(|port| {
            config_tree::context_has_child(
                tree,
                &format!("interface {port}"),
                Some(&format!("switchport trunk vlan {}", spec.vlan_id)),
            )
        })
    {
        return Err(DomainError::InvalidResponse);
    }
    Ok(())
}

/// Refuses whole-context deletion when unrelated children were added after creation.
///
/// # Errors
///
/// Returns [`DomainError::InvalidResponse`] when the running configuration cannot be read
/// (a failed router request is reported this way, not as [`DomainError::Rci`]) or holds
/// children in the segment's contexts that it does not own.
// cancel-safe: only downloads running configuration.
pub(super) async fn check_delete(router: &RouterCtx, view: &SegmentView) -> Result<()> {
    let tree = step::running_config(router)
        .await
        .map_err(|_error| DomainError::InvalidResponse)?;
    let owned = view.delete_summary().owned_contexts;
    let definitions = view.steps();
    let vlan = config_tree::command(&format!("interface Vlan{}", view.spec().id));
    for (context, child) in config_tree::nested(&tree) {
        if owned
            .iter()
            .any(|name| config_tree::command(name) == context.tokens)
        {
            let described = matches!(
                config_tree::texts(&child.tokens).as_slice(),
                ["description", _, ..]
            );
            if context.tokens == vlan && described {
                continue;
            }
            if !definitions
                .iter()
                .any(|definition| definition.owns_child(&context.tokens, &child.tokens))
            {
                return Err(DomainError::InvalidResponse);
            }
        }
    }
    Ok(())
}
