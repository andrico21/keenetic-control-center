//! Shared typed-write verification gate and explicit stateless action inventory.

use kcc_app::workflow::{CliChangeRequest, PresencePredicate, VerificationSpec, WorkflowError};
use kcc_config::config_text::{Token, flatten, parse};
use serde_json::{Value, json};

use crate::{DomainError, Result};

/// Stateless actions and why no readable postcondition can prove their delivery.
pub const ACTIONS_WITHOUT_STATE: &[(&str, &str)] = &[
    (
        "components check-update",
        "Update discovery starts an asynchronous external lookup.",
    ),
    (
        "system configuration fail-safe rollback",
        "Rollback reboots and may remove the current management path.",
    ),
    (
        "ip hotspot wake",
        "Wake packets have no persistent router state.",
    ),
    ("wol", "Wake packets have no persistent router state."),
    (
        "system eject",
        "Ejection can detach the device and its read surface.",
    ),
    (
        "media partition check",
        "A filesystem check starts maintenance without a persistent result field.",
    ),
    (
        "system log clear",
        "The log may immediately refill after clearing.",
    ),
    (
        "system reboot",
        "Reboot disconnects the management session.",
    ),
    (
        "system configuration factory-reset",
        "Factory reset removes the management session and credentials.",
    ),
    (
        "components commit",
        "Firmware commit reboots and invalidates the session.",
    ),
    ("mws member reboot", "Member reboot disconnects the target."),
    (
        "mws member update check",
        "Update discovery starts an asynchronous external lookup.",
    ),
    (
        "mws member update start",
        "Firmware installation starts an asynchronous rebooting action.",
    ),
    (
        "ip http ssl acme get",
        "ACME issuance starts an external asynchronous challenge.",
    ),
    (
        "ip http ssl acme revoke",
        "ACME revocation is an external asynchronous action.",
    ),
];

/// Returns the documented reason when a command has no readable postcondition.
#[inline]
#[must_use]
pub fn action_without_state(path: &str) -> Option<&'static str> {
    ACTIONS_WITHOUT_STATE
        .iter()
        .find_map(|(command, reason)| (*command == path).then_some(*reason))
}

/// Refuses a typed CLI request without verification before any router request.
///
/// # Errors
/// Returns a typed workflow verification error naming the unverified command.
#[inline]
pub fn require(request: &CliChangeRequest) -> Result<()> {
    if request.verify.is_empty() {
        for command in &request.commands {
            if action_without_state(&command.validated().path).is_none() {
                return Err(DomainError::Workflow(WorkflowError::VerificationFailed {
                    field: command.validated().path.clone(),
                }));
            }
        }
    }
    Ok(())
}

/// Completes non-secret typed requests with canonical running-config verification.
///
/// # Errors
/// Refuses undecodable commands and secret-bearing writes without a presence check.
#[inline]
pub fn complete(mut request: CliChangeRequest) -> Result<CliChangeRequest> {
    if request.verify.is_empty() {
        for command in &request.commands {
            let validated = command.validated();
            if action_without_state(&validated.path).is_some() {
                continue;
            }
            if validated.has_secrets() {
                return Err(DomainError::InvalidResponse);
            }
            let line = command
                .expose_for_send()
                .map_err(|_error| DomainError::InvalidResponse)?;
            let (positive, present) = line
                .strip_prefix("no ")
                .map_or((line.as_str(), true), |positive| (positive, false));
            let ast = parse(positive).map_err(|_error| DomainError::InvalidResponse)?;
            let rows = flatten(&ast);
            let [row] = rows.as_slice() else {
                return Err(DomainError::InvalidResponse);
            };
            let words = row
                .tokens
                .iter()
                .map(|token| match token {
                    Token::Word(word) => Ok(json!(word)),
                    Token::Ns3(_) | _ => Err(DomainError::InvalidResponse),
                })
                .collect::<Result<Vec<_>>>()?;
            let mut spec = VerificationSpec::presence(
                Vec::new(),
                validated.path.clone(),
                if present {
                    PresencePredicate::ConfigCommand
                } else {
                    PresencePredicate::ConfigCommandAbsent
                },
            );
            spec.expected = Value::Array(words);
            request.verify.push(spec);
        }
    }
    require(&request)?;
    Ok(request)
}
