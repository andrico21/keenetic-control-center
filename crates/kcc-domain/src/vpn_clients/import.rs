//! Protected WireGuard import planning.

use kcc_app::{
    permissions::Permission,
    workflow::{CliCommand as ValidatedCli, PresencePredicate, VerificationSpec},
};
use kcc_catalog::Risk;

use super::{VpnClientChange, WireGuardConfig, change, import_fields};
use crate::{ChangeOp, DomainError, Result, RouterCtx, cli_token, pointer};

/// Builds the complete import before any mutation can be dispatched.
///
/// # Errors
///
/// Returns [`DomainError::Validation`] when the catalog refuses a command or a key,
/// [`DomainError::InvalidCliToken`] when a name, key or field is not one safe CLI word,
/// [`DomainError::Workflow`] when a rendered line does not match its request,
/// [`DomainError::InvalidResponse`] when a secret command cannot be bound to its template or a
/// field has an unexpected shape, and [`DomainError::Rci`] or [`DomainError::InvalidResponse`]
/// when the management check cannot read the router.
// NOT cancel-safe: it only plans, using read-only topology requests, but it may sign in first, and
// a sign-in dropped mid-way can leave an orphaned router session.
pub(super) async fn plan(
    router: &RouterCtx,
    name: &str,
    config: &WireGuardConfig,
) -> Result<ChangeOp> {
    let mut operation = ChangeOp::new(
        Vec::new(),
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    );
    change::append(
        router,
        &mut operation,
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
                pointer: format!("/{}/private-key", pointer::escape(name)),
            },
        )?,
        None => change::append(
            router,
            &mut operation,
            &VpnClientChange::GenerateWireGuardPrivateKey {
                name: name.to_owned(),
            },
        )?,
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
                pointer: format!("/{}/obfs-key", pointer::escape(name)),
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
                        pointer::escape(name),
                        pointer::escape(&peer.public_key)
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
                        pointer::escape(name),
                        pointer::escape(&peer.public_key)
                    ),
                },
            )?;
        }
    }
    change::classify(router, operation).await
}

/// Plans one existing peer's preshared key alone, verified by its presence marker.
///
/// # Errors
///
/// Returns an error when an argument cannot be one safe router CLI word
/// ([`DomainError::InvalidCliToken`]), when the catalog refuses the key
/// ([`DomainError::Validation`]), or when the command template cannot be rendered
/// ([`DomainError::InvalidResponse`]).
pub(super) fn peer_preshared(
    router: &RouterCtx,
    name: &str,
    public_key: &str,
    key: secrecy::SecretString,
) -> Result<ChangeOp> {
    cli_token::validate(name)?;
    cli_token::validate(public_key)?;
    let mut operation = ChangeOp::new(
        Vec::new(),
        Vec::new(),
        Risk::Write,
        Permission::Write,
        false,
    );
    append_secret(
        router,
        &mut operation,
        SecretImport {
            path: "interface wireguard peer preshared-key",
            argument: "preshared-key",
            template: format!(
                "interface {name} wireguard peer {public_key} preshared-key {{/preshared-key}}"
            ),
            key,
            pointer: format!(
                "/{}/peers/{}/preshared-key",
                pointer::escape(name),
                pointer::escape(public_key)
            ),
        },
    )?;
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
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
fn append_secret(router: &RouterCtx, operation: &mut ChangeOp, input: SecretImport) -> Result<()> {
    let request = router
        .catalog
        .validate_secret(input.path, input.argument, input.key)
        .map_err(|issues| DomainError::Validation { issues })?;
    operation.push(
        ValidatedCli::from_template(request, &input.template)
            .map_err(|_error| DomainError::InvalidResponse)?,
    );
    operation.verify.push(VerificationSpec::presence(
        vec!["show".to_owned(), "interface".to_owned()],
        input.pointer,
        PresencePredicate::Present,
    ));
    Ok(())
}
