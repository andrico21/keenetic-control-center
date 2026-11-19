//! The fake router's local transport: a Unix socket for paused-clock tests, and a TCP leg
//! that delivers every chunk late, as macOS loopback does.
#![cfg(unix)]

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, net::SocketAddr, time::Duration};

    use kcc_rci::{OutboundPolicy, RciError, RouterUrl, auth::Credentials};
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile, outbound::connect_manager,
    };
    use secrecy::SecretString;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::{TcpStream, UnixStream},
        time::{Instant, timeout},
    };

    type TestResult = Result<(), Box<dyn Error>>;

    /// One challenge request, closed by the server after its answer.
    const REQUEST: &[u8] = b"GET /auth HTTP/1.1\r\nHost: fake\r\nConnection: close\r\n\r\n";

    /// Requests per paused-clock run.
    const ROUNDS: usize = 50;

    /// The number of `ROUNDS` sequential authenticated `show version` reads to `address`
    /// that timed out, under kcc's 5 s connect and 30 s read timeouts.
    // NOT cancel-safe: it signs in first, and a sign-in dropped mid-way can leave an orphaned
    // fake session.
    async fn timeouts(
        policy: &OutboundPolicy,
        address: SocketAddr,
    ) -> Result<usize, Box<dyn Error>> {
        let router = format!("http://{address}").parse::<RouterUrl>()?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD),
        );
        let manager = connect_manager(router, credentials, policy).await?;
        let mut timed_out = 0_usize;
        for _ in 0..ROUNDS {
            match manager.get("/rci/show/version").await {
                Ok(response) => assert_eq!(response.status().as_u16(), 200),
                Err(RciError::Timeout) => timed_out = timed_out.saturating_add(1),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(timed_out)
    }

    /// The socket answers a plain HTTP request.
    // NOT cancel-safe: owns a fake router task.
    #[tokio::test]
    async fn serve_local_answers_over_the_socket() -> TestResult {
        let (_address, socket, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .serve_local()?;
        let mut stream = UnixStream::connect(&socket).await?;
        stream.write_all(REQUEST).await?;
        let mut answer = Vec::new();
        let length = timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await??;

        assert!(
            answer
                .get(..length)
                .is_some_and(|read| read.starts_with(b"HTTP/1.1 401"))
        );
        assert_eq!(handle.request_count(), 1);
        handle.shutdown().await?;
        Ok(())
    }

    /// The TCP address still answers, but only after the relay's delivery delay.
    // NOT cancel-safe: owns a fake router task.
    #[tokio::test]
    async fn tcp_leg_answers_after_the_relay_delay() -> TestResult {
        let (address, _socket, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .serve_local()?;
        let mut stream = TcpStream::connect(address).await?;
        let sent = Instant::now();
        stream.write_all(REQUEST).await?;
        let mut answer = Vec::new();
        let length = timeout(Duration::from_secs(10), stream.read_to_end(&mut answer)).await??;

        assert!(sent.elapsed() >= Duration::from_millis(1));
        assert!(
            answer
                .get(..length)
                .is_some_and(|read| read.starts_with(b"HTTP/1.1 401"))
        );
        assert_eq!(handle.request_count(), 1);
        handle.shutdown().await?;
        Ok(())
    }

    /// Under a paused clock, requests redirected to the socket never time out.
    // NOT cancel-safe: owns a fake router task.
    #[tokio::test(start_paused = true)]
    async fn paused_clock_over_the_socket_has_no_spurious_timeouts() -> TestResult {
        let (address, socket, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .serve_local()?;
        let policy = OutboundPolicy::default()
            .with_loopback(true)
            .with_local_socket(address, socket);

        assert_eq!(timeouts(&policy, address).await?, 0);
        handle.shutdown().await?;
        Ok(())
    }

    /// Under a paused clock, requests over the delayed TCP leg time out spuriously: a
    /// client that bypasses the socket fails on Linux as it does on macOS.
    // NOT cancel-safe: owns a fake router task.
    #[tokio::test(start_paused = true)]
    async fn paused_clock_over_the_tcp_leg_times_out() -> TestResult {
        let (address, _socket, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .serve_local()?;
        let policy = OutboundPolicy::default().with_loopback(true);

        assert!(timeouts(&policy, address).await? > 0);
        handle.shutdown().await?;
        Ok(())
    }
}
