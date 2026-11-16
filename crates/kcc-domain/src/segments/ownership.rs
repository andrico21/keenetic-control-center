//! Validation of persisted segment identifiers and deletion ownership.

use core::result::Result as CoreResult;

use kcc_app::{
    permissions::Permission,
    workflow::{
        ChangeSet, CliChangeRequest, CliCommand as ValidatedCli, VerificationSpec, WorkflowError,
    },
};
use kcc_catalog::HttpMethod;
use kcc_config::quoting::quote_cli_text;
use serde_json::json;

use super::{
    SegmentSpec,
    discovery::{SegmentView, VlanId},
    step,
};
use crate::{DomainError, Result, RouterCtx};

/// Writes the ownership marker after the VLAN exists.
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
        .map_err(|_issues| WorkflowError::InvalidResponse)?;
    let quoted = quote_cli_text(marker).map_err(|_error| WorkflowError::InvalidResponse)?;
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
pub(super) fn check_baseline(spec: &SegmentSpec, text: &str) -> Result<()> {
    let bridge = format!("Bridge{}", spec.id);
    if step::context_has_child(text, &format!("ip nat {bridge}"), None)
        || step::context_has_child(text, &format!("ip hotspot policy {bridge} permit"), None)
        || spec.switch_ports.iter().any(|port| {
            step::context_has_child(
                text,
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
// cancel-safe: only downloads running configuration.
pub(super) async fn check_delete(router: &RouterCtx, view: &SegmentView) -> Result<()> {
    let text = step::running_config(router)
        .await
        .map_err(|_error| DomainError::InvalidResponse)?;
    let owned = view.delete_summary().owned_contexts;
    let definitions = view.steps();
    let vlan = format!("interface Vlan{}", view.spec().id);
    let mut context = "";
    for line in text.lines() {
        if !line.starts_with(' ') {
            context = line;
            continue;
        }
        if owned.iter().any(|name| name == context) {
            let child = line.trim();
            if context == vlan && child.starts_with("description ") {
                continue;
            }
            if !definitions
                .iter()
                .any(|definition| definition.owns_child(context, child))
            {
                return Err(DomainError::InvalidResponse);
            }
        }
    }
    Ok(())
}
