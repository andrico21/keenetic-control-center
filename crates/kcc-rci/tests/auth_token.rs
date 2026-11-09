//! Experimental token authentication and explicit password fallback policy.

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
        AuthError, OutboundPolicy, RciError, auth::Credentials, auth_options::Options,
        session::SessionManager,
    };
    use kcc_testkit::auth_fixture::{self, Options as Fixture, Protocol};
    use reqwest::StatusCode;
    use secrecy::SecretString;

    /// Fallible integration result.
    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    /// Every resource request carries the token without any auth endpoint traffic.
    // NOT cancel-safe: owns the fixture through resource requests and logout.
    #[tokio::test]
    async fn token_success_never_calls_auth() -> TestResult {
        let mut fixture = Fixture::default();
        fixture.protocol = Protocol::Token;
        let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
        let mut options = Options::default();
        options.experimental_token = Some(SecretString::from("fixture-token"));
        let manager = SessionManager::connect_with_options(
            format!("http://{address}").parse()?,
            None,
            options,
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?;

        manager.ensure_session().await?;
        assert_eq!(
            manager.get("/rci/show/version").await?.status(),
            StatusCode::OK
        );
        assert_eq!(
            manager.post("/rci/test", &true).await?.status(),
            StatusCode::OK
        );
        manager.logout().await;

        assert_eq!(counts.token_requests.load(Ordering::SeqCst), 2);
        assert_eq!(counts.auth_get.load(Ordering::SeqCst), 0);
        handle.shutdown().await?;
        Ok(())
    }

    /// Password fallback requires credentials and an explicit opt-in together.
    // NOT cancel-safe: each table row owns a fixture and authentication exchange.
    #[tokio::test]
    async fn token_rejection_obeys_fallback_policy() -> TestResult {
        for (credentials_present, token_fallback) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let mut fixture = Fixture::default();
            fixture.protocol = Protocol::Token;
            let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
            let mut options = Options::default();
            options.experimental_token = Some(SecretString::from("rejected-token"));
            options.token_fallback = token_fallback;
            let credentials = credentials_present
                .then(|| Credentials::new("admin".to_owned(), SecretString::from("admin")));
            let manager = SessionManager::connect_with_options(
                format!("http://{address}").parse()?,
                credentials,
                options,
                &OutboundPolicy::default().with_loopback(true),
            )
            .await?;

            let result = manager.get("/rci/show/version").await;

            if credentials_present && token_fallback {
                assert_eq!(result?.status(), StatusCode::OK);
                assert_eq!(counts.auth_get.load(Ordering::SeqCst), 2);
            } else {
                assert!(matches!(
                    result,
                    Err(RciError::Auth(AuthError::TokenRejected))
                ));
                assert_eq!(counts.auth_get.load(Ordering::SeqCst), 0);
            }
            handle.shutdown().await?;
        }
        Ok(())
    }

    /// Debug formatting never exposes the access token.
    #[test]
    fn options_redact_tokens() {
        let mut options = Options::default();
        options.experimental_token = Some(SecretString::from("unique-secret-token"));
        assert!(!format!("{options:?}").contains("unique-secret-token"));
    }
}
