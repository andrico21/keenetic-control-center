//! Todo 31: kcc's authorization server in the Web UI: the protocol routes outside `/ui`
//! and the consent page with its approve and deny.

#[expect(
    dead_code,
    reason = "the shared Web UI test support; this suite needs part of it"
)]
#[path = "support/mod.rs"]
mod support;

#[path = "oauth_routes/harness.rs"]
mod harness;

#[path = "oauth_routes/consent.rs"]
mod consent;

#[path = "oauth_routes/protocol.rs"]
mod protocol;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    use axum::{http::StatusCode, response::Response};
    use serde_json::Value;
    use url::Url;

    use crate::{
        harness::{Harness, ISSUER, REDIRECT, RESOURCE, pkce},
        support::{
            outcome::TestResult,
            page::{header_text, text},
        },
    };

    /// The query pairs of the redirect `response` answered with.
    fn redirected(response: &Response) -> TestResult<Vec<(String, String)>> {
        let target = header_text(response, "location").ok_or("no redirect")?;
        Ok(Url::parse(&target)?.query_pairs().into_owned().collect())
    }

    /// The value of `name` in `pairs`.
    fn value<'pairs>(pairs: &'pairs [(String, String)], name: &str) -> Option<&'pairs str> {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Todo 31: the metadata names the issuer, the endpoints, code with S256 only, public
    /// clients only, the `mcp` scope and the `iss` response parameter.
    #[tokio::test]
    async fn the_metadata_describes_a_public_s256_code_server() -> TestResult {
        let harness = Harness::new("client")?;
        let answer = harness
            .get("/.well-known/oauth-authorization-server", None)
            .await?;
        assert_eq!(answer.status(), StatusCode::OK);
        let metadata: Value = serde_json::from_str(&text(answer).await?)?;
        let expected = serde_json::json!({
            "issuer": ISSUER,
            "authorization_endpoint": format!("{ISSUER}/oauth/authorize"),
            "token_endpoint": format!("{ISSUER}/oauth/token"),
            "registration_endpoint": format!("{ISSUER}/oauth/register"),
            "revocation_endpoint": format!("{ISSUER}/oauth/revoke"),
            "jwks_uri": format!("{ISSUER}/oauth/jwks"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp"],
            "authorization_response_iss_parameter_supported": true,
        });
        assert_eq!(metadata, expected);
        let keys: Value =
            serde_json::from_str(&text(harness.get("/oauth/jwks", None).await?).await?)?;
        assert_eq!(
            keys.pointer("/keys/0/alg").and_then(Value::as_str),
            Some("EdDSA")
        );
        Ok(())
    }

    /// Todo 31: every protocol route and the consent page answer 404 while no listener
    /// signs in with kcc.
    #[tokio::test]
    async fn an_inactive_server_answers_404() -> TestResult {
        let harness = Harness::new("client")?;
        harness.server.activate(None);
        for path in [
            "/.well-known/oauth-authorization-server",
            "/oauth/jwks",
            "/oauth/authorize?response_type=code",
            "/ui/oauth/consent?request=abc",
        ] {
            assert_eq!(
                harness.get(path, None).await?.status(),
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        for path in ["/oauth/token", "/oauth/register", "/oauth/revoke"] {
            assert_eq!(
                harness.protocol(path, &[]).await?.status(),
                StatusCode::NOT_FOUND,
                "{path}"
            );
        }
        Ok(())
    }

    /// Todo 31: a well-addressed refusal goes back to the client with `error`, `state`, `iss`.
    ///
    /// Plain PKCE, no challenge, another response type, another scope, an unknown
    /// resource; an invalid `state` is not echoed.
    #[tokio::test]
    async fn refusals_go_back_with_error_state_and_issuer() -> TestResult {
        let harness = Harness::new("client")?;
        let (_verifier, challenge) = pkce("refusals");
        let client = harness.client.clone();
        let base = |changed: &[(&'static str, &str)]| -> Vec<(String, String)> {
            let mut pairs = vec![
                ("response_type", "code"),
                ("client_id", client.as_str()),
                ("redirect_uri", REDIRECT),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("state", "kept"),
                ("resource", RESOURCE),
            ];
            for (name, new) in changed {
                pairs.retain(|(key, _)| key != name);
                if !new.is_empty() {
                    pairs.push((name, new));
                }
            }
            pairs
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect()
        };
        let cases: [(&[(&str, &str)], &str); 6] = [
            (&[("code_challenge_method", "plain")], "invalid_request"),
            (&[("code_challenge", "")], "invalid_request"),
            (&[("code_challenge_method", "")], "invalid_request"),
            (&[("response_type", "token")], "unsupported_response_type"),
            (&[("scope", "mcp admin")], "invalid_scope"),
            (
                &[("resource", "https://other.example/mcp")],
                "invalid_target",
            ),
        ];
        for (changed, error) in cases {
            let pairs = base(changed);
            let borrowed: Vec<(&str, &str)> = pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect();
            let answer = harness.authorize(&borrowed).await?;
            let query = redirected(&answer)?;
            assert_eq!(value(&query, "error"), Some(error), "{changed:?}");
            assert_eq!(value(&query, "state"), Some("kept"), "{changed:?}");
            assert_eq!(value(&query, "iss"), Some(ISSUER), "{changed:?}");
            assert!(
                header_text(&answer, "location")
                    .unwrap_or_default()
                    .starts_with(REDIRECT)
            );
        }
        let long = "s".repeat(513);
        let pairs = base(&[("state", long.as_str())]);
        let borrowed: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let query = redirected(&harness.authorize(&borrowed).await?)?;
        assert_eq!(value(&query, "error"), Some("invalid_request"));
        assert_eq!(
            value(&query, "state"),
            None,
            "an invalid state is not echoed"
        );
        Ok(())
    }

    /// Todo 31: bad clients, redirect URIs and repeated parameters get an error page.
    ///
    /// An unknown client, a redirect URI the client did not register (another path,
    /// another host, a `javascript:` URI, the registered one with anything appended: A3)
    /// and a repeated parameter (else a valid request) get an error page and never a
    /// redirect.
    #[tokio::test]
    async fn bad_clients_and_redirects_get_an_error_page() -> TestResult {
        let harness = Harness::new("client")?;
        let (_, challenge) = pkce("page");
        let client = harness.client.clone();
        let (slash, letter, dots) = (
            format!("{REDIRECT}/"),
            format!("{REDIRECT}x"),
            format!("{REDIRECT}/../x"),
        );
        let prefixed = [slash.as_str(), letter.as_str(), dots.as_str()]
            .map(|redirect| (client.as_str(), redirect, "web-oauth-error-redirect"));
        for (client_id, redirect, key) in prefixed.into_iter().chain([
            ("ffff", REDIRECT, "web-oauth-error-client"),
            (
                client.as_str(),
                "http://127.0.0.1:9/other",
                "web-oauth-error-redirect",
            ),
            (
                client.as_str(),
                "https://evil.example/callback",
                "web-oauth-error-redirect",
            ),
            (
                client.as_str(),
                "javascript:alert(1)",
                "web-oauth-error-redirect",
            ),
        ]) {
            let answer = harness
                .authorize(&[
                    ("response_type", "code"),
                    ("client_id", client_id),
                    ("redirect_uri", redirect),
                    ("code_challenge", &challenge),
                    ("code_challenge_method", "S256"),
                    ("resource", RESOURCE),
                ])
                .await?;
            assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{redirect}");
            assert_eq!(header_text(&answer, "location"), None, "{redirect}");
            assert!(
                text(answer)
                    .await?
                    .contains(&format!("data-message-key=\"{key}\"")),
                "{redirect}"
            );
        }
        let twice = format!(
            "/oauth/authorize?response_type=code&client_id={client}&redirect_uri={REDIRECT}\
             &code_challenge={challenge}&code_challenge_method=S256&resource={RESOURCE}\
             &state=first&state=second"
        );
        let answer = harness.get(&twice, None).await?;
        assert_eq!(
            answer.status(),
            StatusCode::BAD_REQUEST,
            "a repeated parameter"
        );
        assert_eq!(header_text(&answer, "location"), None);
        assert!(
            text(answer)
                .await?
                .contains("data-message-key=\"web-oauth-error-request\"")
        );
        Ok(())
    }

    /// Todo 31: one address gets at most 30 authorization requests in 10 minutes, so it
    /// cannot evict everybody's pending requests.
    #[tokio::test]
    async fn the_31st_authorization_from_one_address_is_refused() -> TestResult {
        let harness = Harness::new("client")?;
        let (_, challenge) = pkce("flood");
        for _admitted in 0_u32..30 {
            drop(harness.begin(&challenge, "s").await?);
        }
        let refused = harness
            .authorize(&[("response_type", "code"), ("client_id", &harness.client)])
            .await?;
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(header_text(&refused, "location"), None);
        Ok(())
    }

    /// Todo 31: token answers, refusals included, are `no-store` and `no-cache`; the code
    /// needs its verifier.
    #[tokio::test]
    async fn token_answers_are_never_stored() -> TestResult {
        let harness = Harness::new("client")?;
        let (verifier, challenge) = pkce("token");
        let id = harness.begin(&challenge, "s").await?;
        let code = harness.approved_code("alice", &id).await?;
        let wrong = format!("{verifier}x");
        let refused = harness
            .protocol(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", REDIRECT),
                    ("client_id", &harness.client),
                    ("code_verifier", &wrong),
                    ("resource", RESOURCE),
                ],
            )
            .await?;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            header_text(&refused, "cache-control").as_deref(),
            Some("no-store")
        );
        assert_eq!(header_text(&refused, "pragma").as_deref(), Some("no-cache"));
        let refusal: Value = serde_json::from_str(&text(refused).await?)?;
        assert_eq!(
            refusal.get("error").and_then(Value::as_str),
            Some("invalid_grant")
        );
        let second = harness.begin(&challenge, "s").await?;
        let second_code = harness.approved_code("alice", &second).await?;
        let issued = harness
            .protocol(
                "/oauth/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &second_code),
                    ("redirect_uri", REDIRECT),
                    ("client_id", &harness.client),
                    ("code_verifier", &verifier),
                    ("resource", RESOURCE),
                ],
            )
            .await?;
        assert_eq!(issued.status(), StatusCode::OK);
        assert_eq!(
            header_text(&issued, "cache-control").as_deref(),
            Some("no-store")
        );
        assert_eq!(header_text(&issued, "pragma").as_deref(), Some("no-cache"));
        let tokens: Value = serde_json::from_str(&text(issued).await?)?;
        assert_eq!(
            tokens.get("token_type").and_then(Value::as_str),
            Some("Bearer")
        );
        Ok(())
    }
}
