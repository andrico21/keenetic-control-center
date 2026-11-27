//! Continued exchanges: one POST, then `GET` reads of the same resource in the same session
//! while the router marks its answer `continued: true`.

use core::time::Duration;

use kcc_rci::{DecodeDetail, DecodeProblem, RciError, RouterUrl, engine::RciBody};
use serde_json::Value;
use tokio::time::sleep;

use super::{Connection, no_query, show_path};

/// The resource whose target is always the router's own host.
const SELF_PING: &str = "tools/ping";

/// Sends `body` to `path`, then collects at most `max_gets` continuation reads.
///
/// # Errors
///
/// Validation, request, HTTP, decode or RCI errors of any exchange.
// NOT cancel-safe: the POST may start router-side work (a ping, a log stream) whose answer
// is then lost; it may also sign in first.
pub(super) async fn exchange(
    connection: &Connection,
    path: &str,
    body: &Value,
    max_gets: u8,
) -> Result<Vec<Value>, RciError> {
    let resource = show_path(path)?;
    let sent = if path == SELF_PING {
        self_ping(body, &connection.router)?
    } else {
        body.clone()
    };
    let client = &connection.client;
    let first = answer(client.post(&resource, &sent).await?)?;
    collect(first, max_gets, connection.continuation_pause, async || {
        answer(client.get(&resource, &no_query()).await?)
    })
    .await
}

/// `body` with `host` set to the router's own host.
///
/// # Errors
///
/// [`RciError::Validation`] when the router URL has no host or `body` is not an object.
fn self_ping(body: &Value, router: &RouterUrl) -> Result<Value, RciError> {
    let host = router.host().ok_or(RciError::Validation)?;
    let mut sent = body.clone();
    drop(
        sent.as_object_mut()
            .ok_or(RciError::Validation)?
            .insert("host".to_owned(), Value::String(host)),
    );
    Ok(sent)
}

/// One answer as JSON; a text answer becomes a JSON string.
///
/// # Errors
///
/// [`RciError::Decode`] for an answer kind the capture does not know.
fn answer(body: RciBody) -> Result<Value, RciError> {
    match body {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(text) => Ok(Value::String(text)),
        _ => Err(RciError::Decode(DecodeDetail::new(
            "continued answer",
            "$",
            DecodeProblem::Other {
                category: "an answer of another kind",
            },
        ))),
    }
}

/// `first` and then, while the last answer has `continued: true`, at most `max_gets`
/// answers of `next`, each after `pause`.
///
/// # Errors
///
/// The first error of `next`.
// NOT cancel-safe: cancellation drops the answers collected so far and may cut `next` mid-way.
async fn collect<F>(
    first: Value,
    max_gets: u8,
    pause: Duration,
    mut next: F,
) -> Result<Vec<Value>, RciError>
where
    F: AsyncFnMut() -> Result<Value, RciError>,
{
    let mut answers = vec![first];
    for _ in 0..max_gets {
        let continues = answers
            .last()
            .and_then(|last| last.get("continued"))
            .and_then(Value::as_bool)
            == Some(true);
        if !continues {
            break;
        }
        sleep(pause).await;
        answers.push(next().await?);
    }
    Ok(answers)
}

#[cfg(test)]
mod tests {
    //! Continuation stop rules.

    use core::time::Duration;

    use kcc_rci::RciError;
    use serde_json::{Value, json};

    use super::collect;

    /// Collects with no pause from canned answers; also returns the number of reads.
    async fn run(
        first: Value,
        max_gets: u8,
        canned: Vec<Value>,
    ) -> (Result<Vec<Value>, RciError>, usize) {
        let mut queue = canned.into_iter();
        let mut calls = 0_usize;
        let result = collect(first, max_gets, Duration::ZERO, async || {
            calls = calls.saturating_add(1);
            queue.next().ok_or(RciError::NotFound)
        })
        .await;
        (result, calls)
    }

    /// Reads continue while the answer says `continued: true`, stop at the first answer
    /// without it and never exceed `max_gets` (todo 4).
    ///
    /// # Panics
    ///
    /// Panics when a stop rule is broken.
    #[tokio::test]
    async fn continuation_stops_at_the_last_answer_or_the_bound() {
        let more = json!({"continued": true});
        let done = json!({"done": true});
        let (all, all_reads) = run(
            more.clone(),
            30,
            vec![more.clone(), done.clone(), more.clone()],
        )
        .await;
        assert_eq!(
            all.ok(),
            Some(vec![more.clone(), more.clone(), done.clone()]),
            "stops after the last"
        );
        assert_eq!(all_reads, 2, "no read after the last answer");
        let (bounded, bounded_reads) = run(more.clone(), 1, vec![more.clone(), more.clone()]).await;
        assert_eq!(
            bounded.ok(),
            Some(vec![more.clone(), more.clone()]),
            "max_gets bounds the reads"
        );
        assert_eq!(bounded_reads, 1, "one read at most");
        let (single, single_reads) = run(more.clone(), 0, vec![done]).await;
        assert_eq!(
            single.ok(),
            Some(vec![more]),
            "max_gets 0 keeps only the POST answer"
        );
        assert_eq!(single_reads, 0, "no read with max_gets 0");
    }
}
