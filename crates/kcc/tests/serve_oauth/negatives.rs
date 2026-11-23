//! Todo 31 refusals: PKCE and code binding, the redirect URI, the resource, and tokens
//! the kit must refuse.

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::time::Duration;

    use kcc_app::{
        accounts::{Clock as _, SystemClock},
        mcp_auth::{
            clients::ClientStore,
            grants::GrantStore,
            pending::{AuthorizationRequest, CodeTarget, PendingStore, PkceChallenge},
            signing::{AccessClaims, SigningKey, Validity},
        },
    };
    use reqwest::StatusCode;
    use secrecy::{ExposeSecret as _, SecretString};
    use sha2::{Digest as _, Sha256};

    use crate::{
        fixture::{Fixture, Options, TestResult},
        flow::{self, Pkce, REDIRECT, authorize, base64url, begin, client, location, param, query},
        mcp::initialize_status,
        tokens::{error_of, redeem, token},
    };

    /// Todo 31: a wrong verifier is `invalid_grant` and burns the code; a redeemed code
    /// used again is `invalid_grant`; a code bound to another client is `invalid_grant`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pkce_and_code_binding_are_enforced() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let first = client(&fixture, &server).await?;
        let mut consent = begin(&fixture, &server, &first).await?;
        let code = flow::approve(&fixture, &server, &consent, "alice").await?;
        let right = consent.pkce.verifier.clone();
        consent.pkce.verifier = Pkce::new()?.verifier;
        let wrong = redeem(&fixture, &server, &consent, &code).await?;
        assert_eq!(
            error_of(wrong).await?,
            (StatusCode::BAD_REQUEST, "invalid_grant".to_owned())
        );
        consent.pkce.verifier = right;
        let burned = redeem(&fixture, &server, &consent, &code).await?;
        assert_eq!(
            error_of(burned).await?.1,
            "invalid_grant",
            "a refused attempt burns the code"
        );
        let fresh = begin(&fixture, &server, &first).await?;
        let fresh_code = flow::approve(&fixture, &server, &fresh, "alice").await?;
        let redeemed = redeem(&fixture, &server, &fresh, &fresh_code).await?;
        assert_eq!(redeemed.status(), StatusCode::OK, "the control");
        let used = redeem(&fixture, &server, &fresh, &fresh_code).await?;
        assert_eq!(
            error_of(used).await?.1,
            "invalid_grant",
            "a code is used once"
        );
        let bound = begin(&fixture, &server, &first).await?;
        let bound_code = flow::approve(&fixture, &server, &bound, "alice").await?;
        let other = client(&fixture, &server).await?;
        let mut stolen = begin(&fixture, &server, &first).await?;
        stolen.client.clone_from(&other);
        stolen.pkce = Pkce {
            verifier: bound.pkce.verifier.clone(),
            challenge: String::new(),
        };
        let elsewhere = redeem(&fixture, &server, &stolen, &bound_code).await?;
        assert_eq!(
            error_of(elsewhere).await?.1,
            "invalid_grant",
            "bound to its client"
        );
        let plain = authorize(
            &fixture,
            &server,
            &[
                ("response_type", "code"),
                ("client_id", &first),
                ("redirect_uri", REDIRECT),
                ("code_challenge", &fresh.pkce.challenge),
                ("code_challenge_method", "plain"),
                ("state", "s"),
                ("resource", &server.resource()),
            ],
        )
        .await?;
        let refused = query(&location(&plain).ok_or("plain PKCE is answered at the client")?)?;
        assert_eq!(param(&refused, "error"), Some("invalid_request"));
        Ok(())
    }

    /// Todo 31: a redirect URI the client did not register, or an unknown client, gets an
    /// error page and never a redirect; the same holds for a code redeemed with another
    /// redirect URI.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_changed_redirect_uri_gets_an_error_page_not_a_redirect() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let first = client(&fixture, &server).await?;
        let pkce = Pkce::new()?;
        let resource = server.resource();
        for (client_id, redirect) in [
            (first.as_str(), "http://127.0.0.1:9/elsewhere"),
            (first.as_str(), "https://evil.example/callback"),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                REDIRECT,
            ),
        ] {
            let answer = authorize(
                &fixture,
                &server,
                &[
                    ("response_type", "code"),
                    ("client_id", client_id),
                    ("redirect_uri", redirect),
                    ("code_challenge", &pkce.challenge),
                    ("code_challenge_method", "S256"),
                    ("state", "s"),
                    ("resource", &resource),
                ],
            )
            .await?;
            assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{redirect}");
            assert_eq!(location(&answer), None, "{redirect}");
            let page = answer.text().await?;
            assert!(
                page.contains("data-message-key=\"web-oauth-error-"),
                "{page}"
            );
        }
        let consent = begin(&fixture, &server, &first).await?;
        let code = flow::approve(&fixture, &server, &consent, "alice").await?;
        let moved = token(
            &fixture,
            &server,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "http://127.0.0.1:9/elsewhere"),
                ("client_id", &first),
                ("code_verifier", &consent.pkce.verifier),
                ("resource", &resource),
            ],
        )
        .await?;
        assert_eq!(error_of(moved).await?.1, "invalid_grant");
        Ok(())
    }

    /// Todo 31: a resource no listener serves is `invalid_target` at the authorization and
    /// at the token endpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unknown_resource_is_invalid_target() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let first = client(&fixture, &server).await?;
        let pkce = Pkce::new()?;
        let answer = authorize(
            &fixture,
            &server,
            &[
                ("response_type", "code"),
                ("client_id", &first),
                ("redirect_uri", REDIRECT),
                ("code_challenge", &pkce.challenge),
                ("code_challenge_method", "S256"),
                ("state", "kept"),
                ("resource", "https://other.example/mcp"),
            ],
        )
        .await?;
        let pairs = query(&location(&answer).ok_or("answered at the client")?)?;
        assert_eq!(param(&pairs, "error"), Some("invalid_target"));
        assert_eq!(param(&pairs, "state"), Some("kept"));
        assert_eq!(param(&pairs, "iss"), Some(server.issuer().as_str()));
        let consent = begin(&fixture, &server, &first).await?;
        let code = flow::approve(&fixture, &server, &consent, "alice").await?;
        let elsewhere = token(
            &fixture,
            &server,
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("client_id", &first),
                ("code_verifier", &consent.pkce.verifier),
                ("resource", "https://other.example/mcp"),
            ],
        )
        .await?;
        assert_eq!(error_of(elsewhere).await?.1, "invalid_target");
        Ok(())
    }

    /// Todo 31: the kit refuses tokens kcc's sign-in must not accept.
    ///
    /// A header naming `RS256`, another audience, another issuer, all signed with kcc's own
    /// key, are refused; the same token for the server's resource and issuer is accepted
    /// (the control).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn foreign_tokens_are_refused_by_the_kit() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let first = client(&fixture, &server).await?;
        let state = fixture.state()?;
        let clock = Arc::new(SystemClock::default());
        let key = SigningKey::load_or_create(&state, &Fixture::key())?;
        let clients =
            ClientStore::new(state.clone(), Arc::<SystemClock>::clone(&clock)).document()?;
        let registered = clients.client(&first).ok_or("registered")?;
        let mint = |audience: &str, issuer: &str| -> TestResult<String> {
            let pending = PendingStore::new(Arc::<SystemClock>::clone(&clock));
            let verifier = SecretString::from(flow::unique("v"));
            let challenge = PkceChallenge::parse(
                "S256",
                &base64url(&Sha256::digest(verifier.expose_secret().as_bytes()))?,
            )?;
            let target = CodeTarget::new(&first, REDIRECT, audience);
            let request = AuthorizationRequest::new(registered, target.clone(), challenge)?;
            let code = pending.issue_code(request, "alice")?;
            let authorized = pending
                .redeem(&code, &target, &verifier)
                .map_err(|refusal| format!("{refusal:?}"))?;
            let fingerprint = fixture.accounts()?.fingerprint("alice")?.ok_or("alice")?;
            let grants = GrantStore::new(
                state.clone(),
                Arc::<SystemClock>::clone(&clock),
                Duration::from_hours(1),
            );
            let issued = grants.issue(&authorized, &fingerprint)?;
            let now = clock.unix_seconds();
            let claims = AccessClaims::new(
                issuer,
                issued.grant(),
                Validity::new(now, Duration::from_mins(5)),
            );
            Ok(key.mint_access(&claims)?.expose_secret().to_owned())
        };
        let issuer = server.issuer();
        let good = mint(&server.resource(), &issuer)?;
        assert_eq!(
            initialize_status(&fixture, &server, &good).await?,
            StatusCode::OK
        );
        let other_audience = mint("https://other.example/mcp", &issuer)?;
        let other_issuer = mint(&server.resource(), "http://localhost:1")?;
        let (_, rest) = good.split_once('.').ok_or("a JWT")?;
        let rs256 = format!(
            "{}.{rest}",
            base64url(br#"{"alg":"RS256","typ":"at+jwt","kid":"x"}"#)?
        );
        for (name, refused) in [
            ("aud", other_audience),
            ("iss", other_issuer),
            ("RS256", rs256),
        ] {
            assert_eq!(
                initialize_status(&fixture, &server, &refused).await?,
                StatusCode::UNAUTHORIZED,
                "{name}"
            );
        }
        Ok(())
    }
}
