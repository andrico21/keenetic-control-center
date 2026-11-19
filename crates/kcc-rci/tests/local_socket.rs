//! The test-only local-socket hook of the outbound policy: admission first, then the
//! Unix-socket redirect for exactly the registered address.
#![cfg(unix)]

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, net::SocketAddr};
    use std::{net::TcpListener, path::PathBuf};

    use kcc_rci::{
        OutboundPolicy, RciError, RouterUrl, TlsMode, auth::Credentials, session::HttpTimeouts,
    };
    use kcc_testkit::{
        DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, model::Profile, outbound::connect_manager,
    };
    use secrecy::SecretString;

    type TestResult = Result<(), Box<dyn Error>>;

    /// A loopback address nothing listens on: its port was bound once and released.
    fn unbound_loopback() -> Result<SocketAddr, Box<dyn Error>> {
        Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?)
    }

    /// The status of one authenticated `show version` read through `policy` to `address`.
    // NOT cancel-safe: it signs in first, and a sign-in dropped mid-way can leave an orphaned
    // fake session.
    async fn read_version(
        policy: &OutboundPolicy,
        address: SocketAddr,
    ) -> Result<u16, Box<dyn Error>> {
        let router = format!("http://{address}").parse::<RouterUrl>()?;
        let credentials = Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD),
        );
        let manager = connect_manager(router, credentials, policy).await?;
        let response = manager.get("/rci/show/version").await?;
        Ok(response.status().as_u16())
    }

    /// A policy that refuses loopback refuses a registered loopback address exactly as it
    /// refuses an unregistered one.
    #[test]
    fn registration_does_not_admit_a_refused_address() -> TestResult {
        let address = unbound_loopback()?;
        let router = format!("http://{address}").parse::<RouterUrl>()?;
        let plain = OutboundPolicy::default();
        let registered =
            OutboundPolicy::default().with_local_socket(address, PathBuf::from("/nonexistent/s"));
        for policy in [&plain, &registered] {
            let outcome = policy.client_builder_for_resolved(
                &router,
                &TlsMode::Verify,
                HttpTimeouts::default(),
                &[address],
            );
            assert!(matches!(outcome, Err(RciError::Policy)));
        }
        Ok(())
    }

    /// A request to the registered address reaches the fake over its Unix socket although
    /// nothing listens on that TCP port.
    // NOT cancel-safe: owns a fake router task.
    #[tokio::test]
    async fn registered_address_is_dialled_over_the_socket() -> TestResult {
        let (_tcp, socket, handle) = FakeRouter::builder(Profile::default())
            .build()?
            .serve_local()?;
        let address = unbound_loopback()?;
        let policy = OutboundPolicy::default()
            .with_loopback(true)
            .with_local_socket(address, socket);

        let status = read_version(&policy, address).await?;

        assert_eq!(status, 200);
        assert!(handle.request_count() > 0);
        handle.shutdown().await?;
        Ok(())
    }

    /// An address that is not registered still goes over TCP, even when another is.
    // NOT cancel-safe: owns a fake router task.
    #[tokio::test]
    async fn unregistered_address_still_uses_tcp() -> TestResult {
        let (address, handle) = FakeRouter::spawn().await?;
        let policy = OutboundPolicy::default()
            .with_loopback(true)
            .with_local_socket(unbound_loopback()?, PathBuf::from("/nonexistent/s"));

        let status = read_version(&policy, address).await?;

        assert_eq!(status, 200);
        assert!(handle.request_count() > 0);
        handle.shutdown().await?;
        Ok(())
    }
}
