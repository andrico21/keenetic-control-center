//! Every available read operation of every curated domain, one request each.

use core::error::Error;

use kcc_domain::{DomainId, RouterCtx, registry};
use kcc_rci::{RciError, RciPath};

/// How one read ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReadResult {
    /// The router answered.
    Read,
    /// The router does not expose the resource (404).
    Absent,
    /// The router answered with an RCI error status, e.g. a missing argument.
    Refused,
}

/// One read operation and its result.
#[derive(Debug, Clone)]
pub(crate) struct ReadOutcome {
    /// Domain the operation belongs to.
    pub domain: DomainId,
    /// Catalog command of the operation.
    pub command: &'static str,
    /// Result.
    pub result: ReadResult,
}

/// Reads every operation the router's catalog offers, in registry order.
///
/// # Errors
/// Returns transport, authentication or decode failures; RCI statuses are recorded.
// cancel-safe: every request is a read.
pub(crate) async fn read_all(ctx: &RouterCtx) -> Result<Vec<ReadOutcome>, Box<dyn Error>> {
    let mut outcomes = Vec::new();
    for domain in registry() {
        for operation in domain.available_reads(&ctx.catalog) {
            let words = operation
                .catalog_path
                .split_whitespace()
                .collect::<Vec<_>>();
            let path = RciPath::from_segments(&words)?;
            let answer = if words.first() == Some(&"show") {
                ctx.client.show(&path, &()).await
            } else {
                ctx.client.get(&path, &()).await
            };
            let result = match answer {
                Ok(_body) => ReadResult::Read,
                Err(RciError::NotFound) => ReadResult::Absent,
                Err(RciError::Rci {
                    pointer: _,
                    code: _,
                    ident: _,
                    message: _,
                }) => ReadResult::Refused,
                Err(error) => return Err(error.into()),
            };
            outcomes.push(ReadOutcome {
                domain: domain.id,
                command: operation.catalog_path,
                result,
            });
        }
    }
    Ok(outcomes)
}
