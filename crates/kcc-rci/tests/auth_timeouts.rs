//! A read timeout is the same error on every authentication path.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use kcc_rci::{
        OutboundPolicy, RciError,
        auth::Credentials,
        auth_options::{Mode, Options},
        session::Manager,
    };
    use kcc_testkit::auth_fixture::{self, Hang, Options as Fixture, Protocol};
    use secrecy::SecretString;

    /// Fallible integration result.
    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    /// A-15: a router that stops answering times out as `RciError::Timeout` under token,
    /// digest and ndw4 authentication alike.
    // NOT cancel-safe: owns one fixture per authentication path.
    #[tokio::test(start_paused = true)]
    async fn timeout_is_one_error_on_every_auth_path() -> TestResult {
        for path in ["token", "digest", "ndw4"] {
            let mut fixture = Fixture::default();
            let mut options = Options::default();
            match path {
                "token" => {
                    fixture.protocol = Protocol::Token;
                    fixture.hang = Hang::Resources;
                    options.experimental_token =
                        Some(SecretString::from(["fixture", "token"].join("-")));
                }
                "digest" => {
                    fixture.protocol = Protocol::DigestSha256;
                    fixture.hang = Hang::Resources;
                    options.mode = Mode::DigestProxy;
                }
                _ => fixture.hang = Hang::Ndw4Phases,
            }
            let (address, handle, _counts) = auth_fixture::spawn(fixture).await?;
            let manager = Manager::connect_with_options(
                format!("http://{address}").parse()?,
                Some(Credentials::new(
                    "admin".to_owned(),
                    SecretString::from("admin"),
                )),
                options,
                &OutboundPolicy::default().with_loopback(true),
            )
            .await?;

            let result = manager.get("/rci/show/version").await;

            assert!(
                matches!(result, Err(RciError::Timeout)),
                "{path}: {result:?}"
            );
            handle.shutdown().await?;
        }
        Ok(())
    }
}
