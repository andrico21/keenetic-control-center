//! Todo 31: the protocol routes' refusals: prefixed redirect URIs of an `https` client,
//! confidential or implicit registrations, oversized requests and wrong methods.

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
        http::{Method, Request, StatusCode, header},
        response::Response,
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

    /// Asserts `answer` is the token endpoint's refusal: `status`, `Cache-Control:
    /// no-store`, `Pragma: no-cache` and, unless `bodiless`, `invalid_request`.
    async fn refused_as_token_refusal(
        answer: Response,
        status: StatusCode,
        label: &str,
        bodiless: bool,
    ) -> TestResult {
        assert_eq!(answer.status(), status, "{label}");
        assert_eq!(
            header_text(&answer, "cache-control").as_deref(),
            Some("no-store"),
            "{label}"
        );
        assert_eq!(
            header_text(&answer, "pragma").as_deref(),
            Some("no-cache"),
            "{label}"
        );
        if !bodiless {
            let refusal: Value = serde_json::from_str(&text(answer).await?)?;
            assert_eq!(
                refusal.get("error").and_then(Value::as_str),
                Some("invalid_request"),
                "{label}"
            );
        }
        Ok(())
    }

    /// Todo 31 (413 without `Pragma`, N16): a 3 MB request to the token, registration or
    /// revocation endpoint is refused as `invalid_request` with `413`, `Cache-Control:
    /// no-store` and `Pragma: no-cache`.
    #[tokio::test]
    async fn an_oversized_token_request_is_never_stored() -> TestResult {
        let harness = Harness::new("client")?;
        let filler = "a".repeat(3 << 20);
        for (path, content_type, body) in [
            (
                "/oauth/token",
                "application/x-www-form-urlencoded",
                format!("grant_type=refresh_token&refresh_token={filler}"),
            ),
            (
                "/oauth/register",
                "application/json",
                json!({"client_name": filler, "redirect_uris": ["http://127.0.0.1:9/cb"]})
                    .to_string(),
            ),
            (
                "/oauth/revoke",
                "application/x-www-form-urlencoded",
                format!("client_id=x&token={filler}"),
            ),
        ] {
            let answer = harness
                .send(
                    Request::post(path)
                        .header(header::CONTENT_TYPE, content_type)
                        .header(header::CONTENT_LENGTH, body.len())
                        .body(Body::from(body))?,
                )
                .await?;
            refused_as_token_refusal(answer, StatusCode::PAYLOAD_TOO_LARGE, path, false).await?;
        }
        Ok(())
    }

    /// Todo 31 (405 without `Pragma`): a method a protocol route does not take is refused
    /// with `405`, its `Allow` header, `Cache-Control: no-store`, `Pragma: no-cache` and
    /// `invalid_request`.
    #[tokio::test]
    async fn a_wrong_method_is_never_stored() -> TestResult {
        let harness = Harness::new("client")?;
        for (method, path, allow) in [
            (Method::GET, "/oauth/token", "POST"),
            (Method::PUT, "/oauth/token", "POST"),
            (Method::DELETE, "/oauth/token", "POST"),
            (Method::HEAD, "/oauth/token", "POST"),
            (Method::GET, "/oauth/register", "POST"),
            (Method::GET, "/oauth/revoke", "POST"),
            (Method::POST, "/oauth/jwks", "GET,HEAD"),
            (Method::POST, "/oauth/authorize", "GET,HEAD"),
        ] {
            let label = format!("{method} {path}");
            let answer = harness
                .send(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(
                header_text(&answer, "allow").as_deref(),
                Some(allow),
                "{label}"
            );
            refused_as_token_refusal(
                answer,
                StatusCode::METHOD_NOT_ALLOWED,
                &label,
                method == Method::HEAD,
            )
            .await?;
        }
        Ok(())
    }
}
