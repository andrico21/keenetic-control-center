//! The start retry of the shared `kcc serve` test support, against simulated children that
//! bind a loopback port in this process.
#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests return the boxed error of whatever step failed"
)]

#[expect(
    dead_code,
    reason = "the retry needs no child process; the stderr reader is exercised by the serve suites"
)]
#[path = "support/serve_port.rs"]
mod serve_port;

use core::{error::Error, time::Duration};
use std::{net::TcpListener, sync::mpsc};

use serve_port::{START_ATTEMPTS, Start, await_ready, start_on_free_ports};

/// Test result.
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Upper bound for one simulated start.
const LIMIT: Duration = Duration::from_secs(5);

/// A simulated child that binds `port` and logs the outcome the way `kcc serve` does,
/// while another socket holds the port when `taken`.
fn simulated_start(port: u16, taken: bool) -> TestResult<Start<Vec<String>>> {
    let (log, lines) = mpsc::channel();
    let other = taken
        .then(|| TcpListener::bind(("127.0.0.1", port)))
        .transpose()?;
    let logged = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_bound) => format!("INFO kcc listening on 127.0.0.1:{port}"),
        Err(error) => format!("ERROR bind 127.0.0.1:{port}: {error}"),
    };
    drop(other);
    log.send(logged)?;
    Ok(await_ready(
        &lines,
        |line| line.contains("listening"),
        LIMIT,
    )?)
}

/// T-07: a port taken between the pick and the child's bind costs one attempt, not the
/// test: the start is retried on fresh ports until the child listens.
#[test]
fn a_start_on_a_taken_port_is_retried_on_fresh_ports() -> TestResult {
    let mut offered = Vec::new();

    let ([port], seen) = start_on_free_ports(|[port]| {
        offered.push(port);
        simulated_start(port, offered.len() < 3)
    })?;

    assert_eq!(offered.len(), 3, "two taken ports, then a free one");
    assert_eq!(offered.last(), Some(&port), "the ports of the ready start");
    assert_eq!(
        seen,
        vec![format!("INFO kcc listening on 127.0.0.1:{port}")]
    );
    Ok(())
}

/// T-07: the retry is bounded; a port that is always taken fails the start.
#[test]
fn a_start_that_never_binds_fails_after_the_last_attempt() {
    let mut attempts = 0_usize;

    let started: TestResult<([u16; 1], Vec<String>)> = start_on_free_ports(|[port]| {
        attempts = attempts.saturating_add(1);
        simulated_start(port, true)
    });

    assert!(started.is_err(), "no start succeeded");
    assert_eq!(attempts, START_ATTEMPTS);
}
