//! A background operation's dedicated session ends with its handle.

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

use core::{error::Error, net::SocketAddr, str::FromStr as _, time::Duration};

use kcc_rci::{
    DecodeProblem, RciError, RciPath, RouterUrl,
    auth::Credentials,
    engine::{RciBody, RciClient, RciClientOptions},
    outbound::OutboundPolicy,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FakeRouterBuilder, Handle, model::Profile,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::time::{Instant, error::Elapsed, timeout};
use tokio_util::sync::CancellationToken;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// Bound on waiting for the router to see a logout.
const SEEN: Duration = Duration::from_secs(10);

async fn start_router() -> Result<(SocketAddr, Handle, FakeRouter), Box<dyn Error + Send + Sync>> {
    serve(FakeRouter::builder(Profile::default())).await
}

async fn serve(
    builder: FakeRouterBuilder,
) -> Result<(SocketAddr, Handle, FakeRouter), Box<dyn Error + Send + Sync>> {
    let fake = builder.build()?;
    let (address, handle) = fake.clone().serve(([127, 0, 0, 1], 0).into()).await?;
    Ok((address, handle, fake))
}

/// The fake answering `tools/ping` with `answers` in the session continuation.
async fn continued_ping(
    answers: Vec<Value>,
) -> Result<(SocketAddr, Handle, FakeRouter), Box<dyn Error + Send + Sync>> {
    serve(FakeRouter::builder(Profile::default()).continued_fixture("tools/ping", answers)).await
}

/// The requests the router saw with `method` at `/rci/tools/ping`.
fn ping_requests(handle: &Handle, method: &str) -> Vec<kcc_testkit::RequestRecord> {
    handle
        .request_log()
        .into_iter()
        .filter(|record| record.method().as_str() == method && record.path() == "/rci/tools/ping")
        .collect()
}

/// The JSON value of `body`.
fn json_value(body: RciBody) -> Result<Value, Box<dyn Error + Send + Sync>> {
    match body {
        RciBody::Json(response) => Ok(response.value),
        RciBody::Text(_) | _ => Err("the answer is not JSON".into()),
    }
}

async fn client(address: SocketAddr) -> Result<RciClient, RciError> {
    let router =
        RouterUrl::from_str(&format!("http://{address}")).map_err(|_error| RciError::Validation)?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    RciClient::connect_with(router, credentials, options).await
}

fn ping() -> Result<RciPath, RciError> {
    RciPath::from_segments(["tools", "ping"]).map_err(|_error| RciError::Validation)
}

async fn signed_out(handle: &Handle, count: usize) -> Result<(), Elapsed> {
    timeout(SEEN, handle.wait_for_requests("DELETE", "/auth", count)).await
}

/// A-07: finishing a background operation signs its dedicated session out.
#[tokio::test]
async fn a_finished_operation_logs_its_session_out() -> TestResult {
    let (address, handle, _fake) = start_router().await?;
    let client = client(address).await?;
    let process = client
        .start(ping()?, &json!({"host":"192.0.2.1"}))
        .await?
        .with_poll_interval(Duration::from_millis(1));
    drop(process.poll(&CancellationToken::new()).await?);

    signed_out(&handle, 1).await?;
    handle.shutdown().await?;
    Ok(())
}

/// A-07: dropping a handle that never finished signs its dedicated session out.
#[tokio::test]
async fn a_dropped_handle_logs_its_session_out() -> TestResult {
    let (address, handle, _fake) = start_router().await?;
    let client = client(address).await?;
    let process = client.start(ping()?, &json!({"host":"192.0.2.1"})).await?;
    drop(process);

    signed_out(&handle, 1).await?;
    handle.shutdown().await?;
    Ok(())
}

/// A-07: a cancelled operation reports cancellation, not failure or timeout, and the
/// router process is still stopped.
#[tokio::test]
async fn a_cancelled_operation_is_not_a_timeout() -> TestResult {
    let (address, handle, fake) =
        serve(FakeRouter::builder(Profile::default()).process_ids(true)).await?;
    let client = client(address).await?;
    let process = client
        .start(ping()?, &json!({"host":"192.0.2.2"}))
        .await?
        .with_poll_interval(Duration::from_secs(60));
    let token = CancellationToken::new();
    token.cancel();

    assert!(matches!(
        process.poll(&token).await,
        Err(RciError::Cancelled)
    ));
    assert_eq!(fake.stopped_processes(), 1);
    handle.shutdown().await?;
    Ok(())
}

/// The main client's logout ends its session on the router.
#[tokio::test]
async fn the_client_logout_ends_the_router_session() -> TestResult {
    let (address, handle, _fake) = start_router().await?;
    let client = client(address).await?;
    drop(
        client
            .get(&RciPath::from_segments(["show", "system"])?, &())
            .await?,
    );
    client.logout().await;

    signed_out(&handle, 1).await?;
    handle.shutdown().await?;
    Ok(())
}

/// Todo 28: a router that continues in the session is read in that session with one POST.
///
/// The POST answer is the first chunk, every further chunk is a `GET` without a query in
/// the same session, polling ends at the first chunk without `continued`, and no second
/// POST is sent.
#[tokio::test]
async fn a_continued_command_is_read_in_its_session_with_one_post() -> TestResult {
    let (address, handle, _fake) = start_router().await?;
    let client = client(address).await?;
    let process = client
        .start(ping()?, &json!({"host":"192.0.2.1"}))
        .await?
        .with_poll_interval(Duration::from_millis(1));
    let last = json_value(process.poll(&CancellationToken::new()).await?)?;

    assert_eq!(last.get("continued"), None);
    assert_eq!(
        last.get("message"),
        Some(&json!(["ping: output line 5", "ping: output line 6"]))
    );
    assert_eq!(ping_requests(&handle, "POST").len(), 1, "one POST");
    let gets = ping_requests(&handle, "GET");
    assert_eq!(gets.len(), 4, "the POST answer is the first of five chunks");
    assert!(gets.iter().all(|record| record.query().is_empty()));
    assert_eq!(ping_requests(&handle, "DELETE").len(), 0, "no DELETE");
    handle.shutdown().await?;
    Ok(())
}

/// Todo 28: an answer with neither a process id nor `continued: true` is a finished
/// command: polling returns it at once, without a `GET`.
#[tokio::test]
async fn a_finished_answer_is_returned_at_once() -> TestResult {
    let done = json!({"message": ["done"]});
    let (address, handle, _fake) = continued_ping(vec![done.clone()]).await?;
    let client = client(address).await?;
    let process = client.start(ping()?, &json!({"host":"192.0.2.1"})).await?;

    assert_eq!(
        json_value(process.poll(&CancellationToken::new()).await?)?,
        done
    );
    assert_eq!(ping_requests(&handle, "GET").len(), 0, "no GET");
    handle.shutdown().await?;
    Ok(())
}

/// Todo 28: an answer that is no JSON object is still a missing process id.
#[tokio::test]
async fn an_answer_that_is_no_object_lacks_the_process_id() -> TestResult {
    let (address, handle, _fake) = continued_ping(vec![json!(["not", "an object"])]).await?;
    let client = client(address).await?;
    let started = client.start(ping()?, &json!({"host":"192.0.2.1"})).await;

    let Err(RciError::Decode(detail)) = started else {
        return Err("the answer must fail to decode".into());
    };
    assert_eq!(
        detail.problem,
        DecodeProblem::MissingPointer {
            pointer: "/process/id".to_owned()
        }
    );
    handle.shutdown().await?;
    Ok(())
}

/// Todo 28: stopping a continued command signs its dedicated session out (the router ends
/// a session's command with it) and sends no `DELETE` to the command.
///
/// `stop` is called directly: `poll_each` signs the session out itself afterwards, which
/// would hide a `stop` that does not. The handle stays alive until the assertions ran, so
/// its drop cannot provide the sign-out either.
#[tokio::test]
async fn stopping_a_continued_command_signs_its_session_out() -> TestResult {
    let (address, handle, fake) = start_router().await?;
    let client = client(address).await?;
    let process = client.start(ping()?, &json!({"host":"192.0.2.2"})).await?;
    drop(process.next().await?);

    assert_eq!(json_value(process.stop().await?)?, json!({}));
    signed_out(&handle, 1).await?;
    assert_eq!(ping_requests(&handle, "DELETE").len(), 0, "no DELETE");
    assert_eq!(fake.stopped_processes(), 0);
    drop(process);
    handle.shutdown().await?;
    Ok(())
}

/// Todo 28: an answer with a process id and `continued: true` stays in process-id mode.
#[tokio::test]
async fn a_process_id_wins_over_continued() -> TestResult {
    let both = json!({"process": {"id": "7"}, "continued": true});
    let (address, handle, _fake) = continued_ping(vec![both]).await?;
    let client = client(address).await?;
    let process = client.start(ping()?, &json!({"host":"192.0.2.1"})).await?;

    assert!(format!("{process:?}").contains("process_id: Some(\"7\")"));
    drop(process);
    handle.shutdown().await?;
    Ok(())
}

/// Todo 28: `poll_each` hands over every chunk in order, the POST answer first, and
/// returns the last one.
#[tokio::test]
async fn poll_each_sees_every_chunk_in_order() -> TestResult {
    let chunks = vec![
        json!({"message": ["a", "b"], "continued": true}),
        json!({"message": ["c"], "continued": true}),
        json!({"continued": true}),
        json!({"message": ["d"]}),
    ];
    let (address, handle, _fake) = continued_ping(chunks.clone()).await?;
    let client = client(address).await?;
    let process = client
        .start(ping()?, &json!({"host":"192.0.2.1"}))
        .await?
        .with_poll_interval(Duration::from_millis(1));
    let mut handed = Vec::new();
    let last = process
        .poll_each(&CancellationToken::new(), |chunk| {
            handed.push(chunk.clone());
        })
        .await?;

    let seen: Vec<Value> = handed
        .into_iter()
        .map(json_value)
        .collect::<Result<_, _>>()?;
    assert_eq!(seen, chunks);
    assert_eq!(Some(&json_value(last)?), chunks.last());
    assert_eq!(ping_requests(&handle, "POST").len(), 1, "one POST");
    assert_eq!(
        ping_requests(&handle, "GET").len(),
        3,
        "one GET per further chunk"
    );
    handle.shutdown().await?;
    Ok(())
}

/// Todo 28: a command that never stops continuing ends with `Timeout` at the deadline,
/// and its session is signed out without a `DELETE` to the command.
#[tokio::test]
async fn a_never_ending_command_times_out_at_the_deadline() -> TestResult {
    let more = json!({"message": ["tick"], "continued": true});
    let (address, handle, _fake) = continued_ping(vec![more]).await?;
    let client = client(address).await?;
    let process = client
        .start(ping()?, &json!({"host":"192.0.2.1"}))
        .await?
        .with_poll_interval(Duration::from_millis(5))
        .with_deadline(Duration::from_millis(200));

    // The outer bound is far below the 300 s default deadline, so a deadline that is
    // ignored fails here instead of hanging.
    let started = Instant::now();
    let outcome = timeout(
        Duration::from_secs(30),
        process.poll(&CancellationToken::new()),
    )
    .await
    .map_err(|_elapsed| "the poll did not end at its own deadline")?;

    assert!(matches!(outcome, Err(RciError::Timeout)));
    assert!(started.elapsed() < Duration::from_secs(5), "ended late");
    signed_out(&handle, 1).await?;
    assert_eq!(ping_requests(&handle, "DELETE").len(), 0, "no DELETE");
    handle.shutdown().await?;
    Ok(())
}
