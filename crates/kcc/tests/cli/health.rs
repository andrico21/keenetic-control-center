//! `kcc healthcheck` against a running `kcc serve`, over TLS and plain HTTP.

use core::{error::Error, time::Duration};
use std::{
    io::{BufRead as _, BufReader},
    net::TcpListener,
    process::Child,
    sync::mpsc,
    thread,
};

use super::support::{Env, TestResult};

/// Longest wait for the server to listen.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// A running `kcc serve`, killed on drop.
struct Server {
    /// The process.
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// A free loopback port.
fn free_port() -> Result<u16, Box<dyn Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

/// Starts `kcc serve` and returns once it logged that it listens.
fn serve(env: &Env) -> Result<Server, Box<dyn Error>> {
    let config = env.path("kcc.toml");
    let mut child = env
        .command(&[
            "--config",
            config.to_str().ok_or("non-UTF-8 path")?,
            "serve",
        ])
        .spawn()?;
    let stderr = child.stderr.take().ok_or("stderr unavailable")?;
    let server = Server { child };
    let (sender, receiver) = mpsc::channel();
    drop(thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    }));
    loop {
        let line = receiver.recv_timeout(START_TIMEOUT)?;
        if line.contains("listening") {
            drop(thread::spawn(move || receiver.into_iter().for_each(drop)));
            return Ok(server);
        }
    }
}

/// The `[server]` table on `port`, with listener TLS when `tls` names the PEM files.
fn server_table(port: u16, tls: Option<(&str, &str)>) -> String {
    let listener = format!("[server]\nlisten_addr = \"127.0.0.1\"\nlisten_port = {port}\n");
    match tls {
        Some((cert, key)) => {
            format!("{listener}tls_cert_path = {cert:?}\ntls_key_path = {key:?}\n")
        }
        None => listener,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthcheck_over_plain_http_on_loopback() -> TestResult {
    let port = free_port()?;
    let env = Env::new(&server_table(port, None))?;
    let down = env.kcc(&["healthcheck"])?;
    assert_eq!(down.code, 1_i32, "nothing listens yet: {down:?}");
    let _server = serve(&env)?;
    let up = env.kcc(&["healthcheck"])?;
    assert_eq!(up.code, 0_i32, "{up:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthcheck_over_tls_trusts_exactly_the_configured_certificate() -> TestResult {
    let env = Env::new("")?;
    let certs = env.path("certs");
    let other = env.path("other");
    for dir in [&certs, &other] {
        let made = env.kcc_bare(&[
            "tls",
            "self-signed",
            "--host",
            "localhost",
            "--out-dir",
            dir.to_str().ok_or("non-UTF-8 path")?,
        ])?;
        assert_eq!(made.code, 0_i32, "{made:?}");
        assert!(made.stdout.contains("SHA-256"), "{made:?}");
    }
    let port = free_port()?;
    let cert = certs.join("kcc-cert.pem");
    let key = certs.join("kcc-key.pem");
    let cert_text = cert.to_str().ok_or("non-UTF-8 path")?;
    let key_text = key.to_str().ok_or("non-UTF-8 path")?;
    env.write_config(&server_table(port, Some((cert_text, key_text))))?;
    let _server = serve(&env)?;
    let up = env.kcc(&["healthcheck"])?;
    assert_eq!(up.code, 0_i32, "{up:?}");
    let other_cert = other.join("kcc-cert.pem");
    let pinned_elsewhere = server_table(
        port,
        Some((other_cert.to_str().ok_or("non-UTF-8 path")?, key_text)),
    );
    let wrong = Env::new(&pinned_elsewhere)?;
    let refused = wrong.kcc(&["healthcheck"])?;
    assert_eq!(
        refused.code, 1_i32,
        "another certificate must not be trusted: {refused:?}"
    );
    Ok(())
}
