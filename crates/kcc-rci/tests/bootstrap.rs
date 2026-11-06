//! Factory-setup authentication and client transition contracts.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "integration assertions establish authentication boundaries"
)]
mod tests {
    use core::{error::Error, str::FromStr as _};

    use kcc_rci::{OutboundPolicy, RciClient, RciClientOptions, RouterUrl, auth::Credentials};
    use kcc_testkit::{FakeRouter, model::Profile};
    use secrecy::SecretString;

    /// Passwordless setup is opt-in and the new password works through a fresh session.
    // NOT cancel-safe: mutates an isolated fake router.
    #[tokio::test]
    async fn first_password_requires_explicit_bootstrap_then_fresh_authentication()
    -> Result<(), Box<dyn Error>> {
        let (address, handle) = FakeRouter::builder(Profile::default())
            .user("admin", "", ["cli", "http"])
            .build()?
            .serve(([127, 0, 0, 1], 0).into())
            .await?;
        let url = RouterUrl::from_str(&format!("http://{address}"))?;
        let options = RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true));
        let empty = Credentials::new("admin".to_owned(), SecretString::from(String::new()));
        let ordinary = RciClient::connect_with(url.clone(), empty.clone(), options.clone()).await?;
        assert!(
            ordinary.detect().await.is_err(),
            "ordinary authentication must refuse passwordless setup"
        );
        let setup = RciClient::connect_bootstrap_with(url.clone(), empty, options).await?;
        assert!(setup.is_bootstrap().await?);
        drop(
            setup
                .parse("user admin password plain changed-password")
                .await?,
        );
        let new = Credentials::new(
            "admin".to_owned(),
            SecretString::from("changed-password".to_owned()),
        );
        let authenticated = setup.retarget(url, Some(new)).await?;
        assert!(!authenticated.is_bootstrap().await?);
        let info = authenticated.detect().await?;
        assert_eq!(info.hw_id(), Some("KN-1811"));
        assert!(
            ordinary.detect().await.is_err(),
            "old password must stop working"
        );
        assert!(!handle.running_config_text().contains("changed-password"));
        let forbidden = RouterUrl::from_str("http://169.254.169.254")?;
        assert!(
            authenticated.retarget(forbidden, None).await.is_err(),
            "retarget must preserve policy"
        );
        handle.shutdown().await?;
        Ok(())
    }
}
