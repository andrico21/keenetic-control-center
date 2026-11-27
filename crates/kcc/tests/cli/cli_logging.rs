//! `RUST_LOG` makes the short-lived commands log on stderr; `serve` and `mcp stdio` keep
//! their own logging and an untouched stdout.

use core::{error::Error, net::SocketAddr, time::Duration};
use std::{io::Write as _, process::Stdio};

use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter};
use serde_json::{Value, json};

use super::{
    serve_port::{Start, await_ready, free_ports, start_on_free_ports, stderr_lines},
    spawning,
    support::{Env, Run, TestResult, finish, router},
};

/// Longest wait for the server to listen.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs `kcc <args>` with `RUST_LOG` set to `filter`.
fn kcc_logging(env: &Env, filter: &str, args: &[&str]) -> Result<Run, Box<dyn Error>> {
    let config = env.path("kcc.toml");
    let mut all = vec!["--config", config.to_str().ok_or("non-UTF-8 path")?];
    all.extend_from_slice(args);
    let mut command = env.command(&all);
    let _: &mut _ = command.env("RUST_LOG", filter);
    finish(spawning::spawn(&mut command)?)
}

/// An environment with a router profile `lab` for the fake router at `address`.
fn lab(address: SocketAddr) -> Result<Env, Box<dyn Error>> {
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    env.write_config(&router("lab", address, &password))?;
    Ok(env)
}

/// Regression (todo 10): with `RUST_LOG` set, a command logs its router requests on stderr
/// and stdout stays the one JSON document.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_log_puts_router_requests_on_stderr_and_keeps_stdout_json() -> TestResult {
    let (address, fake) = FakeRouter::spawn().await?;
    let env = lab(address)?;

    let run = kcc_logging(&env, "kcc_rci=debug", &["--json", "show", "version"])?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    assert!(
        run.stderr.contains("path=/rci/show/version"),
        "stderr: {}",
        run.stderr
    );
    let documents = serde_json::Deserializer::from_str(&run.stdout)
        .into_iter::<Value>()
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(documents.len(), 1_usize, "stdout: {}", run.stdout);
    fake.shutdown().await?;
    Ok(())
}

/// Regression (todo 10): without `RUST_LOG` a successful command writes nothing to stderr.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_rust_log_stderr_stays_empty() -> TestResult {
    let (address, fake) = FakeRouter::spawn().await?;
    let env = lab(address)?;

    let run = env.kcc(&["--json", "show", "version"])?;

    assert_eq!(run.code, 0_i32, "{run:?}");
    assert_eq!(run.stderr, "", "{run:?}");
    fake.shutdown().await?;
    Ok(())
}

/// Regression (todo 10): a router that refuses the connection is named in the detail line.
#[test]
fn a_refused_connection_is_named_in_the_failure_detail() -> TestResult {
    let [port] = free_ports()?;
    let env = Env::new("")?;
    let password = env.write("router.password", DEFAULT_PASSWORD)?;
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    env.write_config(&router("lab", address, &password))?;

    let run = env.kcc(&["--router", "lab", "router", "test"])?;

    assert_eq!(run.code, 6_i32, "{run:?}");
    assert!(
        run.stderr.to_lowercase().contains("connection refused"),
        "{run:?}"
    );
    Ok(())
}

/// Regression (todo 10): `RUST_LOG` does not stop `kcc serve` from installing its own
/// logging; the server answers its health check.
#[test]
fn serve_with_rust_log_reaches_a_healthy_server() -> TestResult {
    let env = Env::new("")?;
    let config_path = env.path("kcc.toml");
    let path = config_path.to_str().ok_or("non-UTF-8 path")?;
    let (_ports, mut child) = start_on_free_ports(|[port]| -> TestResult<Start<_>> {
        env.write_config(&format!(
            "[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n"
        ))?;
        let mut command = env.command(&["--config", path, "serve"]);
        let _: &mut _ = command.env("RUST_LOG", "info,kcc_rci=debug");
        let mut child = spawning::spawn(&mut command)?;
        let lines = stderr_lines(&mut child)?;
        let started = await_ready(&lines, |line| line.contains("listening"), START_TIMEOUT)?;
        Ok(match started {
            Start::Ready(_seen) => Start::Ready((child, lines)),
            Start::AddressInUse => Start::AddressInUse,
        })
    })?;
    let health = env.kcc(&["healthcheck"]);
    drop(child.0.kill());
    drop(child.0.wait());
    assert_eq!(health?.code, 0_i32);
    Ok(())
}

/// Regression (todo 10): `RUST_LOG=debug` leaves the stdout of `kcc mcp stdio` to JSON-RPC.
#[test]
fn mcp_stdio_with_rust_log_answers_initialize_on_a_clean_stdout() -> TestResult {
    let env = Env::new("[mcp]\nstdio_enabled = true\nstdio_role = \"admin\"\n")?;
    let config = env.path("kcc.toml");
    let mut command = env.command(&[
        "--config",
        config.to_str().ok_or("non-UTF-8 path")?,
        "mcp",
        "stdio",
    ]);
    let _: &mut _ = command.env("RUST_LOG", "debug").stdin(Stdio::piped());
    let mut child = spawning::spawn(&mut command)?;
    let mut stdin = child.stdin.take().ok_or("child stdin")?;
    let initialize = json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"logging","version":"1"}}});
    writeln!(stdin, "{initialize}")?;
    stdin.flush()?;
    drop(stdin);

    let run = finish(child)?;

    let lines = run.stdout.lines().collect::<Vec<_>>();
    assert!(!lines.is_empty(), "no answer: {run:?}");
    for line in lines {
        let message: Value = serde_json::from_str(line)
            .map_err(|error| format!("stdout line {line:?} is not JSON: {error}"))?;
        assert_eq!(message.get("jsonrpc"), Some(&json!("2.0")), "{line}");
    }
    assert!(run.stdout.contains("\"id\":1"), "{run:?}");
    Ok(())
}
