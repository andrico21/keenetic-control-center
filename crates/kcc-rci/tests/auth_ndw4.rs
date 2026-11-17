//! ndw4 protocol acceptance, hostile replies, and downgrade prevention.

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
    use kcc_testkit::auth_fixture::{self, Options as Fixture};
    use reqwest::StatusCode;
    use secrecy::SecretString;
    use serde_json::json;

    /// Fallible integration result.
    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    /// Creates the fixed fixture identity.
    fn credentials(password: &str) -> Credentials {
        Credentials::new("admin".to_owned(), SecretString::from(password.to_owned()))
    }

    /// Mutual authentication completes and authorizes resource access with raw decimal costs.
    // NOT cancel-safe: owns a local test server through the whole scenario.
    #[tokio::test]
    async fn ndw4_success_preserves_raw_cost_strings() -> TestResult {
        let mut fixture = Fixture::default();
        fixture.iterations = json!("02");
        fixture.memory = json!("0064");
        let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
        let manager = Manager::connect(
            format!("http://{address}").parse()?,
            credentials("admin"),
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?;

        let response = manager.get("/rci/show/version").await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counts.auth_get.load(Ordering::SeqCst), 2);
        assert_eq!(counts.phase_three.load(Ordering::SeqCst), 1);
        assert_eq!(counts.ndw2_posts.load(Ordering::SeqCst), 0);
        handle.shutdown().await?;
        Ok(())
    }

    /// Wrong credentials never downgrade to an advertised legacy protocol.
    // NOT cancel-safe: owns a local test server through the whole scenario.
    #[tokio::test]
    async fn wrong_password_rejected_without_ndw2_downgrade() -> TestResult {
        let (address, handle, counts) = auth_fixture::spawn(Fixture::default()).await?;
        let manager = Manager::connect(
            format!("http://{address}").parse()?,
            credentials("wrong"),
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?;

        let result = manager.ensure_session().await;

        assert!(matches!(result, Err(RciError::Auth(AuthError::Rejected))));
        assert_eq!(counts.ndw2_posts.load(Ordering::SeqCst), 0);
        assert_eq!(counts.phase_three.load(Ordering::SeqCst), 0);
        handle.shutdown().await?;
        Ok(())
    }

    /// A forged server signature prevents the final confirmation even with a valid password.
    // NOT cancel-safe: owns a local test server through the whole scenario.
    #[tokio::test]
    async fn signature_mismatch_stops_before_phase_three() -> TestResult {
        let mut fixture = Fixture::default();
        fixture.tamper_signature = true;
        let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
        let manager = Manager::connect(
            format!("http://{address}").parse()?,
            credentials("admin"),
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?;

        let result = manager.ensure_session().await;

        assert!(matches!(
            result,
            Err(RciError::Auth(AuthError::ServerSignatureMismatch))
        ));
        assert_eq!(counts.phase_three.load(Ordering::SeqCst), 0);
        assert_eq!(counts.ndw2_posts.load(Ordering::SeqCst), 0);
        handle.shutdown().await?;
        Ok(())
    }

    /// The local policy refuses a protocol-valid but locally excessive memory request.
    // NOT cancel-safe: owns a local test server through the whole scenario.
    #[tokio::test]
    async fn memory_cap_refuses_before_proof() -> TestResult {
        let (address, handle, counts) = auth_fixture::spawn(Fixture::default()).await?;
        let mut options = Options::default();
        options.max_argon2_memory_kib = 32;
        let manager = Manager::connect_with_options(
            format!("http://{address}").parse()?,
            Some(credentials("admin")),
            options,
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?;

        let result = manager.ensure_session().await;

        assert!(matches!(
            result,
            Err(RciError::Auth(AuthError::CostTooHigh))
        ));
        assert_eq!(counts.phase_two.load(Ordering::SeqCst), 0);
        handle.shutdown().await?;
        Ok(())
    }

    /// A-14: by default a router may ask for 16 Argon2 iterations; 17 is refused before any
    /// proof is sent.
    // NOT cancel-safe: owns a local test server for each table row.
    #[tokio::test]
    async fn default_iteration_cap_is_sixteen() -> TestResult {
        for (iterations, accepted) in [(16_u32, true), (17_u32, false)] {
            let mut fixture = Fixture::default();
            fixture.iterations = json!(iterations);
            let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
            let manager = Manager::connect(
                format!("http://{address}").parse()?,
                credentials("admin"),
                &OutboundPolicy::default().with_loopback(true),
            )
            .await?;

            let result = manager.ensure_session().await;

            if accepted {
                assert!(result.is_ok(), "{iterations}: {result:?}");
                assert_eq!(counts.phase_three.load(Ordering::SeqCst), 1);
            } else {
                assert!(
                    matches!(result, Err(RciError::Auth(AuthError::CostTooHigh))),
                    "{iterations}: {result:?}"
                );
                assert_eq!(counts.phase_two.load(Ordering::SeqCst), 0);
            }
            handle.shutdown().await?;
        }
        Ok(())
    }

    /// A-14: a raised local cap admits 17 iterations; a cap above the protocol maximum of 64
    /// is refused when the manager is built.
    // NOT cancel-safe: owns a local test server through one login.
    #[tokio::test]
    async fn raised_iteration_cap_admits_seventeen() -> TestResult {
        let mut fixture = Fixture::default();
        fixture.iterations = json!(17_u32);
        let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
        let mut options = Options::default();
        options.max_argon2_iterations = 17;
        let manager = Manager::connect_with_options(
            format!("http://{address}").parse()?,
            Some(credentials("admin")),
            options.clone(),
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?;

        manager.ensure_session().await?;
        options.max_argon2_iterations = 65;
        let above = Manager::connect_with_options(
            format!("http://{address}").parse()?,
            Some(credentials("admin")),
            options,
            &OutboundPolicy::default().with_loopback(true),
        )
        .await;

        assert_eq!(counts.phase_three.load(Ordering::SeqCst), 1);
        assert!(matches!(above, Err(RciError::Validation)));
        handle.shutdown().await?;
        Ok(())
    }

    /// Boundary validation rejects malformed nonce, salt, costs, and either error field.
    // NOT cancel-safe: owns a local test server for each table row.
    #[tokio::test]
    async fn hostile_challenges_are_rejected() -> TestResult {
        for case in 0_u8..9 {
            let mut fixture = Fixture::default();
            match case {
                0 => fixture.tamper_nonce = true,
                1 => fixture.tamper_salt = true,
                2 => fixture.iterations = json!(0_u32),
                3 => fixture.iterations = json!(65_u32),
                4 => fixture.memory = json!(7_u32),
                5 => fixture.memory = json!(0x0004_0001_u32),
                6 => fixture.iterations = json!("+2"),
                7 => fixture.memory = json!("64.0"),
                _ => fixture.short_error = true,
            }
            let (address, handle, counts) = auth_fixture::spawn(fixture).await?;
            let manager = Manager::connect(
                format!("http://{address}").parse()?,
                credentials("admin"),
                &OutboundPolicy::default().with_loopback(true),
            )
            .await?;

            let result = manager.ensure_session().await;

            assert!(
                matches!(result, Err(RciError::Auth(AuthError::Rejected))),
                "challenge case {case}"
            );
            assert_eq!(counts.phase_two.load(Ordering::SeqCst), 0);
            assert_eq!(counts.ndw2_posts.load(Ordering::SeqCst), 0);
            handle.shutdown().await?;
        }
        Ok(())
    }

    /// Explicit ndw2 configuration overrides automatic preference.
    // NOT cancel-safe: owns a local test server through the whole scenario.
    #[tokio::test]
    async fn forced_ndw2_is_honored() -> TestResult {
        let (address, handle, counts) = auth_fixture::spawn(Fixture::default()).await?;
        let mut options = Options::default();
        options.mode = Mode::Ndw2;
        let manager = Manager::connect_with_options(
            format!("http://{address}").parse()?,
            Some(credentials("admin")),
            options,
            &OutboundPolicy::default().with_loopback(true),
        )
        .await?;

        let response = manager.get("/rci/show/version").await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(counts.ndw2_posts.load(Ordering::SeqCst), 1);
        assert_eq!(counts.phase_two.load(Ordering::SeqCst), 0);
        handle.shutdown().await?;
        Ok(())
    }
}
