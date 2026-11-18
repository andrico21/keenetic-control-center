//! Request-log fidelity: every root parser line is kept and attributed to its own request.

mod support;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::time::Duration;

    use axum::http::Method;
    use kcc_testkit::{FaultInjection, Handle, RequestRecord, leak, model::Profile};
    use tokio::time::timeout;

    use crate::support::{TestResult, json, spawned};

    /// Bound on every wait of these tests.
    const BOUND: Duration = Duration::from_secs(30);

    /// Root parser requests logged so far, in arrival order.
    fn root_posts(handle: &Handle) -> Vec<RequestRecord> {
        handle
            .request_log()
            .into_iter()
            .filter(|record| record.method() == Method::POST && record.path() == "/rci/")
            .collect()
    }

    /// T-03, T-04: a parser batch logs every line of the request in order, and the
    /// secret-bearing `crypto ike key` line is redacted.
    // NOT cancel-safe: the fixture owns router tasks and sends configuration writes.
    #[tokio::test]
    async fn batch_keeps_every_line_and_redacts_ike_key() -> TestResult {
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        let psk = format!("ike-psk-{}", 7_u8);
        let lines = [
            "interface Bridge7 description one".to_owned(),
            "interface Bridge7 description two".to_owned(),
            format!("crypto ike key office {psk} any"),
        ];

        let answers = client.parse_batch(&lines).await?;

        assert!(
            answers.iter().all(Result::is_ok),
            "batch refused: {answers:?}"
        );
        let posts = root_posts(&handle);
        let batch = posts.last().ok_or("missing batch request")?;
        assert_eq!(
            batch.commands().collect::<Vec<_>>(),
            [
                lines.first().map(String::as_str),
                lines.get(1).map(String::as_str),
                None
            ]
        );
        assert!(!leak::contains_secret(&format!("{posts:?}"), &psk));
        handle.shutdown().await?;
        Ok(())
    }

    /// T-03: two overlapping parser requests each keep their own line, even when the second
    /// is logged before the first one's body is applied.
    // NOT cancel-safe: the fixture owns router tasks and sends configuration writes.
    #[tokio::test]
    async fn overlapping_requests_keep_their_own_lines() -> TestResult {
        let (handle, client) = spawned(Profile::default(), FaultInjection::default()).await?;
        // Signs in first: a sign-in request held by the stall would keep the first line unsent.
        drop(json(
            client
                .parse("interface Bridge7 description signed-in")
                .await?,
        )?);
        let before = root_posts(&handle).len();
        let (first, second) = (
            "interface Bridge7 description first",
            "interface Bridge7 description second",
        );
        let stall = handle.stall();

        let sent_first = client.parse(first);
        let sent_second = async {
            handle.wait_for_requests("POST", "/rci/", before + 1).await;
            client.parse(second).await
        };
        let release = async {
            handle.wait_for_requests("POST", "/rci/", before + 2).await;
            drop(stall);
        };
        let (answer_first, answer_second, ()) = timeout(BOUND, async {
            tokio::join!(sent_first, sent_second, release)
        })
        .await?;

        drop(json(answer_first?)?);
        drop(json(answer_second?)?);
        let posts = root_posts(&handle);
        let lines: Vec<Vec<Option<&str>>> = posts
            .iter()
            .skip(before)
            .map(|record| record.commands().collect())
            .collect();
        assert_eq!(lines, [[Some(first)], [Some(second)]]);
        handle.shutdown().await?;
        Ok(())
    }
}
