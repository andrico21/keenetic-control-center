//! Protected WireGuard import planning.

use kcc_app::{
    permissions::Permission,
    workflow::{CliCommand as ValidatedCli, PresencePredicate, VerificationSpec},
};
use kcc_catalog::Risk;
use serde_json::json;

use super::{VpnClientChange, WireGuardConfig, change, import_fields};
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// Builds the complete import before any mutation can be dispatched.
pub(super) fn plan(router: &RouterCtx, name: &str, config: &WireGuardConfig) -> Result<ChangeOp> {
    let mut operation = change::plan(
        router,
        &VpnClientChange::Create {
            name: name.to_owned(),
        },
    )?;
    match &config.interface.private_key {
        Some(key) => append_secret(
            router,
            &mut operation,
            SecretImport {
                path: "interface wireguard private-key",
                argument: "private-key",
                template: format!("interface {name} wireguard private-key {{/private-key}}"),
                key: key.clone(),
                pointer: format!("/{}/private-key", escape(name)),
            },
        )?,
        None => operation.requests.extend(
            change::plan(
                router,
                &VpnClientChange::GenerateWireGuardPrivateKey {
                    name: name.to_owned(),
                },
            )?
            .requests,
        ),
    }
    import_fields::append(router, name, config, &mut operation)?;
    if let Some(key) = &config.interface.obfuscation_key {
        append_secret(
            router,
            &mut operation,
            SecretImport {
                path: "interface wireguard obfs-key",
                argument: "obfs-key",
                template: format!("interface {name} wireguard obfs-key {{/obfs-key}}"),
                key: key.clone(),
                pointer: format!("/{}/obfs-key", escape(name)),
            },
        )?;
    }
    for peer in &config.peers {
        if let Some(key) = &peer.obfuscation_key {
            append_secret(
                router,
                &mut operation,
                SecretImport {
                    path: "interface wireguard peer obfs-key",
                    argument: "obfs-key",
                    template: format!(
                        "interface {name} wireguard peer {} obfs-key {{/obfs-key}}",
                        peer.public_key
                    ),
                    key: key.clone(),
                    pointer: format!(
                        "/{}/peers/{}/obfs-key",
                        escape(name),
                        escape(&peer.public_key)
                    ),
                },
            )?;
        }
        if let Some(key) = &peer.preshared_key {
            append_secret(
                router,
                &mut operation,
                SecretImport {
                    path: "interface wireguard peer preshared-key",
                    argument: "preshared-key",
                    template: format!(
                        "interface {name} wireguard peer {} preshared-key {{/preshared-key}}",
                        peer.public_key
                    ),
                    key: key.clone(),
                    pointer: format!(
                        "/{}/peers/{}/preshared-key",
                        escape(name),
                        escape(&peer.public_key)
                    ),
                },
            )?;
        }
    }
    operation.risk = Risk::Write;
    operation.permission = Permission::Write;
    Ok(operation)
}

/// A secret slot and the corresponding presence-only observation.
struct SecretImport {
    /// Catalog command.
    path: &'static str,
    /// Catalog argument.
    argument: &'static str,
    /// Public template containing no secret material.
    template: String,
    /// Owned key.
    key: secrecy::SecretString,
    /// Read-back pointer.
    pointer: String,
}

/// Appends a validated secret and its read-back expectation.
fn append_secret(router: &RouterCtx, operation: &mut ChangeOp, input: SecretImport) -> Result<()> {
    let mut request = router
        .catalog
        .validate_secret(input.path, input.argument, input.key)
        .map_err(|issues| DomainError::Validation { issues })?;
    drop(
        ValidatedCli::from_template(request.clone(), &input.template)
            .map_err(|_error| DomainError::InvalidResponse)?,
    );
    request.value = json!({"line": input.template, "arguments": request.value});
    operation.requests.push(request);
    operation.verify.push(VerificationSpec::presence(
        vec!["show".to_owned(), "interface".to_owned()],
        input.pointer,
        PresencePredicate::Present,
    ));
    Ok(())
}

/// Escapes an identifier for a JSON pointer segment.
fn escape(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}
