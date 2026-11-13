//! Digest authentication against an independent HTTP proxy verifier.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, sync::atomic::Ordering};

    use kcc_rci::{
        AuthError, OutboundPolicy, RciError,
        auth::Credentials,
        auth_options::{Mode, Options},
        session::Manager,
    };
    use kcc_testkit::auth_fixture::{self, Options as Fixture, Protocol};
    use reqwest::StatusCode;
    use secrecy::SecretString;

    /// Fallible integration result.
    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    /// MD5 and SHA-256 bind the method, full query, cnonce, and increasing nonce count.
    // NOT cancel-safe: owns a fixture through multiple authenticated requests.
    #[tokio::test]
    async fn digest_success_signs_each_request() -> TestResult {
        for protocol in [Protocol::DigestMd5, Protocol::DigestSha256] {
            let mut fixture = Fixture::default();
            fixture.protocol = protocol;
            let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
            let mut options = Options::default();
            options.mode = Mode::DigestProxy;
            let credentials = Credentials::new("admin".to_owned(), SecretString::from("admin"));
            let manager = Manager::connect_with_options(
                format!("http://{address}").parse()?,
                Some(credentials),
                options,
                &OutboundPolicy::default().with_loopback(true),
            )
            .await?;

            assert_eq!(
                manager
                    .get("/rci/show/interface?name=Bridge0")
                    .await?
                    .status(),
                StatusCode::OK
            );
            assert_eq!(
                manager
                    .post("/rci/test?name=Bridge1", &true)
                    .await?
                    .status(),
                StatusCode::OK
            );

            assert_eq!(counts.digest_requests.load(Ordering::SeqCst), 2);
            assert_eq!(counts.auth_get.load(Ordering::SeqCst), 0);
            handle.shutdown().await?;
        }
        Ok(())
    }

    /// Wrong digest credentials are rejected without a cookie-auth fallback.
    // NOT cancel-safe: owns a fixture through authentication.
    #[tokio::test]
    async fn digest_wrong_password_is_rejected() -> TestResult {
        let mut fixture = Fixture::default();
        fixture.protocol = Protocol::DigestSha256;
        let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
        let mut options = Options::default();
        options.mode = Mode::DigestProxy;
        let credentials = Credentials::new("admin".to_owned(), SecretString::from("wrong"));
        let manager = Manager::connect_with_options(
            format!("http://{address}").parse()?,
            Some(credentials),
            options,
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?;

        let result = manager.get("/rci/show/version").await;

        assert!(matches!(result, Err(RciError::Auth(AuthError::Rejected))));
        assert_eq!(counts.auth_get.load(Ordering::SeqCst), 0);
        handle.shutdown().await?;
        Ok(())
    }
}
