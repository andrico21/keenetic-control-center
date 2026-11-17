//! Show reads that fall back to POST for resources a router refuses to serve by GET.

use serde::Serialize;
use serde_json::{Map, Value};

use super::{RciBody, RciClient};
use crate::{RciError, RciPath, encode_query, session::lock};

/// Reads `path` by GET, or by POST with the query as its body when GET is refused.
///
/// A path is remembered as POST-only when its GET was refused by method (405) or answered 404
/// without a query; a 404 for one query only falls back for that read. A remembered path
/// whose POST is refused the same way is forgotten, so the next read tries GET again.
///
/// # Errors
/// Returns request or response-processing errors.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, both GET and fallback POST are read-only show operations.
pub(super) async fn read<T>(
    client: &RciClient,
    path: &RciPath,
    query: &T,
) -> Result<RciBody, RciError>
where
    T: Serialize + Sync + ?Sized,
{
    let key = path.to_string();
    let body = query_body(query)?;
    if lock(&client.post_only_show).contains(&key) {
        let result = client.post(path, &body).await;
        if matches!(result, Err(RciError::NotFound | RciError::MethodNotAllowed)) {
            let _: bool = lock(&client.post_only_show).remove(&key);
        }
        return result;
    }
    let refusal = match client.get(path, query).await {
        Err(refusal @ (RciError::NotFound | RciError::MethodNotAllowed)) => refusal,
        result => return result,
    };
    let result = client.post(path, &body).await;
    let resource_refused = matches!(refusal, RciError::MethodNotAllowed)
        || body.as_object().is_some_and(Map::is_empty);
    if result.is_ok() && resource_refused {
        let _: bool = lock(&client.post_only_show).insert(key);
    }
    result
}

/// The query as a JSON object of its text values, the POST form of a show read.
///
/// # Errors
/// Returns validation errors when the query cannot be serialized.
fn query_body<T>(query: &T) -> Result<Value, RciError>
where
    T: Serialize + ?Sized,
{
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(&encode_query(query)?).map_err(|_error| RciError::Validation)?;
    Ok(Value::Object(
        pairs
            .into_iter()
            .map(|(name, text)| (name, Value::String(text)))
            .collect(),
    ))
}
