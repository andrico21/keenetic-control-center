//! `resources/list` and `resources/read` over a lab session.

use rmcp::{ServiceError, model::ReadResourceRequestParams};
use serde_json::Value;

use super::lab::{Lab, TestResult};

/// Every resource URI the session lists.
///
/// # Errors
/// Returns the protocol error of `resources/list`.
pub(crate) async fn uris(lab: &Lab) -> TestResult<Vec<String>> {
    Ok(lab
        .client
        .list_all_resources()
        .await?
        .into_iter()
        .map(|resource| resource.uri)
        .collect())
}

/// Reads `uri`: `Ok(json)` for the text contents, `Err(code)` for a protocol error.
///
/// # Errors
/// Returns transport failures and contents that are not JSON text.
pub(crate) async fn read(lab: &Lab, uri: &str) -> TestResult<Result<Value, String>> {
    match lab
        .client
        .read_resource(ReadResourceRequestParams::new(uri))
        .await
    {
        Ok(result) => {
            let contents = serde_json::to_value(&result.contents)?;
            let text = contents
                .pointer("/0/text")
                .and_then(Value::as_str)
                .ok_or("resource returned no text")?;
            Ok(Ok(serde_json::from_str(text)?))
        }
        Err(ServiceError::McpError(error)) => Ok(Err(error.message.into_owned())),
        Err(other) => Err(other.into()),
    }
}
