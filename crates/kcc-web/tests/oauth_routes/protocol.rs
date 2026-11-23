//! Todo 31: the protocol routes' refusals: prefixed redirect URIs of an `https` client,
//! confidential or implicit registrations, and an oversized token request.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use kcc_app::mcp_auth::clients::{ClientRegistration, ClientStore, ClientsDocument};
    use serde_json::{Value, json};

    use crate::{
        harness::{Harness, RESOURCE, pkce},
        support::{
            base::Frozen,
            outcome::TestResult,
            page::{header_text, text},
        },
    };

    /// Todo 31 (A3): an `https` client's registered redirect URI with anything appended
    /// (a slash, a character, a dot segment) gets an error page, never a redirect.
    #[tokio::test]
    async fn an_https_redirect_matches_exactly() -> TestResult {
        let harness = Harness::new("client")?;
        let registered = "https://app.example/cb";
        let client = ClientStore::new(harness.state().clone(), Arc::new(Frozen::at(1)))
            .register(&ClientRegistration::new(None, vec![registered.to_owned()]))?;
        let (_, challenge) = pkce("https");
        let pairs = |redirect: &'static str| {
            [
                ("response_type", "code"),
                ("client_id", client.id()),
                ("redirect_uri", redirect),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
                ("resource", RESOURCE),
            ]
        };
        let accepted = harness.authorize(&pairs("https://app.example/cb")).await?;
        assert_eq!(accepted.status(), StatusCode::SEE_OTHER, "the exact URI");
        for redirect in [
            "https://app.example/cbx",
            "https://app.example/cb/",
            "https://app.example/cb/../x",
        ] {
            let answer = harness.authorize(&pairs(redirect)).await?;
            assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{redirect}");
            assert_eq!(header_text(&answer, "location"), None, "{redirect}");
            assert!(
                text(answer)
                    .await?
                    .contains("data-message-key=\"web-oauth-error-redirect\""),
                "{redirect}"
            );
        }
        Ok(())
    }

    /// Todo 31 (R1): a confidential client, the implicit grant and the `token` response
    /// type are refused with `invalid_client_metadata`, and nothing is stored.
    #[tokio::test]
    async fn only_public_code_clients_register() -> TestResult {
        let harness = Harness::new("client")?;
        let stored = || -> TestResult<usize> {
            Ok(harness
                .state()
                .read::<ClientsDocument>()?
                .map_or(0, |document| document.clients().len()))
        };
        let before = stored()?;
        for changed in [
            json!({"token_endpoint_auth_method": "client_secret_basic"}),
            json!({"grant_types": ["implicit"]}),
            json!({"response_types": ["token"]}),
        ] {
            let mut metadata = json!({
                "client_name": "confidential",
                "redirect_uris": ["http://127.0.0.1:9/cb"],
            });
            for (name, value) in changed.as_object().ok_or("an object")? {
                drop(
                    metadata
                        .as_object_mut()
                        .ok_or("an object")?
                        .insert(name.clone(), value.clone()),
                );
            }
            let answer = harness
                .send(
                    Request::post("/oauth/register")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(metadata.to_string()))?,
                )
                .await?;
            assert_eq!(answer.status(), StatusCode::BAD_REQUEST, "{changed}");
            let body: Value = serde_json::from_str(&text(answer).await?)?;
            assert_eq!(
                body.get("error").and_then(Value::as_str),
                Some("invalid_client_metadata"),
                "{changed}"
            );
        }
        assert_eq!(stored()?, before, "nothing is stored");
        Ok(())
    }

    /// Todo 31 (413 without `Pragma`): a 3 MB token request is refused as
    /// `invalid_request` with `413`, `Cache-Control: no-store` and `Pragma: no-cache`.
    #[tokio::test]
    async fn an_oversized_token_request_is_never_stored() -> TestResult {
        let harness = Harness::new("client")?;
        let body = format!(
            "grant_type=refresh_token&refresh_token={}",
            "a".repeat(3 << 20)
        );
        let answer = harness
            .send(
                Request::post("/oauth/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::CONTENT_LENGTH, body.len())
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(answer.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            header_text(&answer, "cache-control").as_deref(),
            Some("no-store")
        );
        assert_eq!(header_text(&answer, "pragma").as_deref(), Some("no-cache"));
        let refusal: Value = serde_json::from_str(&text(answer).await?)?;
        assert_eq!(
            refusal.get("error").and_then(Value::as_str),
            Some("invalid_request")
        );
        Ok(())
    }
}
