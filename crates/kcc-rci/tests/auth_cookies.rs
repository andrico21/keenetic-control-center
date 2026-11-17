//! Session cookie refresh from router answers.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, net::SocketAddr, sync::atomic::Ordering};

    use kcc_rci::{OutboundPolicy, auth::Credentials, session::Manager};
    use kcc_testkit::auth_fixture::{self, Options as Fixture};
    use reqwest::StatusCode;
    use secrecy::SecretString;

    /// Fallible integration result.
    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    /// Connects a default ndw4 manager to a fixture at `address`.
    // NOT cancel-safe: DNS resolution may finish after cancellation.
    async fn manager(address: SocketAddr) -> Result<Manager, Box<dyn Error + Send + Sync>> {
        Ok(Manager::connect(
            format!("http://{address}").parse()?,
            Credentials::new("admin".to_owned(), SecretString::from("admin")),
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?)
    }

    /// A-02: a 401 carrying a new pending `Set-Cookie` does not replace the session cookie,
    /// so the manager signs in again and the replay succeeds.
    // NOT cancel-safe: owns a fixture through two logins.
    #[tokio::test]
    async fn unauthorized_answer_cookie_is_not_installed() -> TestResult {
        let mut fixture = Fixture::default();
        fixture.expire_with_cookie = true;
        let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
        let manager = manager(address).await?;

        let response = manager.get("/rci/show/version").await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counts.phase_three.load(Ordering::SeqCst), 2);
        handle.shutdown().await?;
        Ok(())
    }

    /// A-02: a malformed refresh of the session cookie on an applied POST is not an error,
    /// and the current cookie keeps working.
    // NOT cancel-safe: owns a fixture through a login and two requests.
    #[tokio::test]
    async fn malformed_refresh_on_applied_post_is_not_an_error() -> TestResult {
        let mut fixture = Fixture::default();
        fixture.resource_set_cookie = Some(b"AUTHFIXTURE=; Max-Age=0".to_vec());
        let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
        let manager = manager(address).await?;

        let posted = manager.post("/rci/system", &true).await?;
        let read = manager.get("/rci/show/version").await?;

        assert_eq!(posted.status(), StatusCode::OK);
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(counts.phase_three.load(Ordering::SeqCst), 1);
        handle.shutdown().await?;
        Ok(())
    }

    /// N5: an unrelated `Set-Cookie` that is not visible ASCII does not fail an applied POST.
    // NOT cancel-safe: owns a fixture through a login and one POST.
    #[tokio::test]
    async fn unrelated_non_ascii_cookie_is_ignored() -> TestResult {
        let mut fixture = Fixture::default();
        fixture.resource_set_cookie = Some(b"tracking=caf\xc3\xa9; Path=/".to_vec());
        let (address, handle, _counts) = auth_fixture::spawn(fixture).await?;
        let manager = manager(address).await?;

        let posted = manager.post("/rci/system", &true).await?;

        assert_eq!(posted.status(), StatusCode::OK);
        handle.shutdown().await?;
        Ok(())
    }
}
