//! Credentials stored in the running configuration: their presence, and whether a write
//! replaced them, checked without copying or revealing a value.

use core::str::from_utf8;

use kcc_rci::{ConfigKind, RciClient, SecretBytes};
use secrecy::ExposeSecret as _;
use subtle::ConstantTimeEq as _;

use super::{PresencePredicate, VerificationSpec, WorkflowError};

/// The running configuration read before a write that replaces a credential, kept only
/// in wiped storage; empty when no expectation of the write needs it.
#[derive(Default)]
pub(super) struct Baseline(Option<SecretBytes>);

impl Baseline {
    /// Reads the running configuration when one of `specs` compares a credential with
    /// the one it replaces, and sends nothing otherwise. A failed read is the error, so
    /// the write whose effect it could not prove is never sent.
    // cancel-safe: only reads router state.
    pub(super) async fn capture(
        client: &RciClient,
        specs: &[VerificationSpec],
    ) -> Result<Self, WorkflowError> {
        if !specs
            .iter()
            .any(|spec| spec.predicate == Some(PresencePredicate::ConfigSecretReplaced))
        {
            return Ok(Self(None));
        }
        Ok(Self(Some(
            client.download_config(ConfigKind::Running).await?,
        )))
    }
}

/// Requires the credential named by `spec` to be present in `text`, without reading it.
pub(super) fn present(text: &str, spec: &VerificationSpec) -> Result<(), WorkflowError> {
    credential(text, spec).map(|_payload| ())
}

/// Finds the stored credential payload named by `spec` in `text`, borrowed and never
/// copied, or fails naming the field.
fn credential<'text>(
    text: &'text str,
    spec: &VerificationSpec,
) -> Result<&'text str, WorkflowError> {
    spec.expected
        .as_str()
        .and_then(|prefix| stored(text, prefix))
        .ok_or_else(|| WorkflowError::VerificationFailed {
            field: spec.field.clone(),
        })
}

/// Requires the credential named by `spec` to be present in `text` and to differ from the
/// one `baseline` held, if it held one.
///
/// The two payloads are compared in constant time inside their wiped buffers. Without a
/// captured baseline the change cannot be proven, so it fails.
pub(super) fn replaced(
    text: &str,
    spec: &VerificationSpec,
    baseline: &Baseline,
) -> Result<(), WorkflowError> {
    let current = credential(text, spec)?;
    let unchanged = || WorkflowError::VerificationFailed {
        field: spec.field.clone(),
    };
    let captured = baseline.0.as_ref().ok_or_else(unchanged)?;
    let before =
        from_utf8(captured.expose_secret()).map_err(|_error| WorkflowError::UndecodableConfig)?;
    let same = credential(before, spec)
        .is_ok_and(|previous| bool::from(previous.as_bytes().ct_eq(current.as_bytes())));
    if same {
        return Err(unchanged());
    }
    Ok(())
}

/// The bounded nonempty payload, without an `ns3 ` marker, of the line that continues the
/// command words `prefix` in configuration `text`, nested contexts included.
fn stored<'text>(text: &'text str, prefix: &str) -> Option<&'text str> {
    let mut contexts = Vec::<(usize, &str)>::new();
    text.lines().find_map(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('!') || trimmed.is_empty() {
            return None;
        }
        let indent = line.len().saturating_sub(trimmed.len());
        contexts.retain(|(depth, _)| *depth < indent);
        let remaining = contexts.iter().try_fold(prefix, |rest, (_, context)| {
            rest.strip_prefix(context)?.strip_prefix(' ')
        });
        let found = remaining
            .and_then(|rest| trimmed.strip_prefix(rest))
            .and_then(|tail| tail.strip_prefix(' '))
            .map(|payload| payload.trim_prefix("ns3 "))
            .filter(|payload| !payload.is_empty() && payload.len() <= 512);
        contexts.push((indent, trimmed));
        found
    })
}
