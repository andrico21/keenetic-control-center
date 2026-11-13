//! The request budget and a dropped connection leave a held bracket running to its end.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions are not rendered API documentation"
)]

use alloc::sync::Arc;
use core::{error::Error, future, time::Duration};
use std::sync::Mutex;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Error as HttpError, Request, StatusCode},
    middleware,
    routing::get,
};
use kcc_app::brackets::Brackets;
use tokio::{sync::oneshot, time::sleep};
use tower::ServiceExt as _;

use super::{budget, hold, own};
use crate::REQUEST_TIMEOUT;

/// Fallible test result.
type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// One bracket, driven by the test: it holds and arms, waits for `close`, then disarms.
struct Script {
    /// Signalled once the request holds its bracket.
    armed: Mutex<Option<oneshot::Sender<()>>>,
    /// Released by the test: the slow end of the bracket (its receipts) is over.
    close: Mutex<Option<oneshot::Receiver<()>>>,
    /// Signalled by the disarm.
    disarmed: Mutex<Option<oneshot::Sender<()>>>,
}

/// The test's ends of a [`Script`].
struct Driver {
    /// The request holds its bracket.
    armed: oneshot::Receiver<()>,
    /// Lets the bracket end.
    close: oneshot::Sender<()>,
    /// The disarm was sent.
    disarmed: oneshot::Receiver<()>,
}

/// A script and its driver.
fn script() -> (Arc<Script>, Driver) {
    let (armed_tx, armed) = oneshot::channel();
    let (close, close_rx) = oneshot::channel();
    let (disarmed_tx, disarmed) = oneshot::channel();
    let script = Script {
        armed: Mutex::new(Some(armed_tx)),
        close: Mutex::new(Some(close_rx)),
        disarmed: Mutex::new(Some(disarmed_tx)),
    };
    (
        Arc::new(script),
        Driver {
            armed,
            close,
            disarmed,
        },
    )
}

/// The handler of a management change, reduced to its bracket: it holds its request,
/// then enters the process-wide count as the change workflow's bracket does.
async fn bracket(script: Arc<Script>, brackets: Brackets) -> &'static str {
    if !hold() {
        return "refused";
    }
    let _open = brackets.enter();
    let armed = script.armed.lock().ok().and_then(|mut slot| slot.take());
    let close = script.close.lock().ok().and_then(|mut slot| slot.take());
    let disarmed = script.disarmed.lock().ok().and_then(|mut slot| slot.take());
    if let Some(sender) = armed {
        let _sent = sender.send(());
    }
    if let Some(receiver) = close {
        drop(receiver.await);
    }
    if let Some(sender) = disarmed {
        let _sent = sender.send(());
    }
    "closed"
}

/// The two layers the Web UI puts around its bounded routes, around `/` (the bracket)
/// and `/stuck` (a request that never holds one and never answers).
fn app(brackets: &Brackets, script: Arc<Script>) -> Router {
    let count = brackets.clone();
    Router::new()
        .route(
            "/",
            get(move || bracket(Arc::clone(&script), count.clone())),
        )
        .route("/stuck", get(future::pending::<&'static str>))
        .layer(middleware::from_fn(budget))
        .layer(middleware::from_fn(own))
}

/// `GET path`.
fn get_request(path: &str) -> Result<Request<Body>, HttpError> {
    Request::get(path).body(Body::empty())
}

/// The budget runs out while the held bracket is still closing: the answer is the
/// handler's own, after the disarm, not the budget's 408.
#[tokio::test(start_paused = true)]
async fn the_budget_waits_for_a_held_bracket() -> TestResult {
    let brackets = Brackets::default();
    let (script, driver) = script();
    let pending = tokio::spawn(app(&brackets, script).oneshot(get_request("/")?));
    driver.armed.await?;
    sleep(REQUEST_TIMEOUT.saturating_add(Duration::from_secs(1))).await;
    assert_eq!(
        brackets.drain(Duration::ZERO).await,
        1,
        "counted while held"
    );
    assert!(driver.close.send(()).is_ok(), "the bracket waits");

    let response = pending.await??;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64).await?;
    assert_eq!(body.as_ref(), b"closed".as_slice());
    driver.disarmed.await?;
    assert_eq!(
        brackets.drain(Duration::ZERO).await,
        0,
        "released at its end"
    );
    Ok(())
}

/// The connection stops waiting after the arm: the server-owned task still closes the
/// bracket, and the count keeps it until then.
#[tokio::test(start_paused = true)]
async fn a_dropped_request_still_closes_its_bracket() -> TestResult {
    let brackets = Brackets::default();
    let (script, driver) = script();
    let pending = tokio::spawn(app(&brackets, script).oneshot(get_request("/")?));
    driver.armed.await?;
    pending.abort();
    assert!(pending.await.is_err_and(|error| error.is_cancelled()));
    assert_eq!(brackets.drain(Duration::ZERO).await, 1, "still held");
    assert!(driver.close.send(()).is_ok(), "the bracket waits");

    driver.disarmed.await?;
    assert_eq!(brackets.drain(Duration::from_secs(1)).await, 0);
    Ok(())
}

/// A request that holds no bracket keeps the 408 budget, and a request outside the
/// owner layer cannot hold one.
#[tokio::test(start_paused = true)]
async fn an_unheld_request_keeps_the_budget() -> TestResult {
    let brackets = Brackets::default();
    let (script, _driver) = script();
    let response = app(&brackets, script)
        .oneshot(get_request("/stuck")?)
        .await?;
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    assert!(!hold(), "no owner, no bracket");
    Ok(())
}
