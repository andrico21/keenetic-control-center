//! Ordered root batches, split into chunks below the router's request budget.

use core::mem::take;

use reqwest::Method;
use serde_json::Value;
use thiserror::Error;

use super::{RciClient, admit::Admission, response_json};
use crate::{DecodeDetail, DecodeProblem, RciError, RciResponse};

/// Maximum serialized request size used for one batch chunk.
const BATCH_BYTES: usize = 900 * 1024;

/// A batch that stopped at a failed chunk, with the answers of the chunks before it.
///
/// The router applied every completed chunk; whether it applied the failed one is unknown.
#[derive(Debug, Error)]
#[error("RCI batch stopped: {error}")]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "callers handle it next to RciError, outside this module"
)]
pub struct BatchError {
    /// Per-item answers of the chunks completed before the failure, in item order.
    pub completed: Vec<Result<RciResponse, RciError>>,
    /// Why the batch stopped.
    #[source]
    pub error: RciError,
}

impl From<BatchError> for RciError {
    #[inline]
    fn from(failure: BatchError) -> Self {
        failure.error
    }
}

/// Sends `items` chunk by chunk and pairs every item with its own answer.
///
/// # Errors
/// Returns the answers so far with the error of the first chunk that could not be sent,
/// answered or matched item by item (a reply of another length is [`RciError::Decode`]).
// NOT cancel-safe: completed chunks may have mutated the router before cancellation.
pub(super) async fn run(
    client: &RciClient,
    items: Vec<Value>,
) -> Result<Vec<Result<RciResponse, RciError>>, BatchError> {
    let chunks = chunks(items).map_err(|error| BatchError {
        completed: Vec::new(),
        error,
    })?;
    let mut completed = Vec::new();
    for chunk in chunks {
        let expected = chunk.len();
        let body = Value::Array(chunk);
        let answered =
            match Admission::take(&client.semaphore, client.options.observer.as_deref()).await {
                Ok(admission) => admission.report_logged(
                    (&client.journal, &Method::POST, "/rci/"),
                    async {
                        let response = client.session.post("/rci/", &body).await?;
                        let Value::Array(values) =
                            response_json(response, client.options.response_bytes).await?
                        else {
                            return Err(RciError::Decode(DecodeDetail::new(
                                "batch answer",
                                "$",
                                DecodeProblem::Other {
                                    category: "batch answer item has another shape",
                                },
                            )));
                        };
                        if values.len() != expected {
                            return Err(RciError::Decode(DecodeDetail::new(
                                "batch answer",
                                "$",
                                DecodeProblem::Length {
                                    expected,
                                    got: values.len(),
                                },
                            )));
                        }
                        Ok(values)
                    }
                    .await,
                ),
                Err(error) => Err(error),
            };
        match answered {
            Ok(values) => completed.extend(values.into_iter().map(RciResponse::from_value)),
            Err(error) => return Err(BatchError { completed, error }),
        }
    }
    Ok(completed)
}

/// Splits items so every serialized array remains below the router request budget.
///
/// # Errors
///
/// Returns validation errors for an unserializable or individually oversized item.
fn chunks(items: Vec<Value>) -> Result<Vec<Vec<Value>>, RciError> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    let mut bytes = 2_usize;
    for item in items {
        let item_bytes = serde_json::to_vec(&item).map_err(|_error| RciError::Validation)?;
        let added = item_bytes
            .len()
            .saturating_add(usize::from(!current.is_empty()));
        if item_bytes.len().saturating_add(2) >= BATCH_BYTES {
            return Err(RciError::Validation);
        }
        if bytes.saturating_add(added) >= BATCH_BYTES && !current.is_empty() {
            chunks.push(take(&mut current));
            bytes = 2;
        }
        bytes = bytes.saturating_add(added);
        current.push(item);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    Ok(chunks)
}
