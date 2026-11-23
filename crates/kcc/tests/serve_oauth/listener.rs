//! Todo 31 listener rules.
//!
//! The OAuth routes exist only while a listener signs in with kcc, the internal JWKS
//! listener holds its port on both loopback addresses, and no secret of the flow reaches
//! the log or the state directory.

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::{io, net::TcpListener};

    use reqwest::{Method, StatusCode};
    use serde_json::Value;

    use crate::{
        browser::{Browser, hx_redirect},
        fixture::{Fixture, Options, PASSWORD, TestResult},
        flow::{begin, client, param, query},
        mcp::Session,
        tokens::{self, redeem, refresh, tokens_of},
    };

    /// Todo 31: while no listener uses kcc sign-in, every OAuth route answers 404.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn while_no_listener_uses_kcc_the_oauth_routes_answer_404() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options {
            kcc: false,
            level: "info",
        })?;
        for (method, path) in [
            (Method::GET, "/.well-known/oauth-authorization-server"),
            (Method::GET, "/oauth/authorize?response_type=code"),
            (Method::GET, "/oauth/jwks"),
            (Method::POST, "/oauth/token"),
            (Method::POST, "/oauth/register"),
            (Method::POST, "/oauth/revoke"),
            (Method::GET, "/ui/oauth/consent?request=abc"),
        ] {
            let answer = fixture
                .http()
                .request(method, format!("{}{path}", server.base()))
                .send()
                .await?;
            assert_eq!(answer.status(), StatusCode::NOT_FOUND, "{path}");
        }
        Ok(())
    }

    /// Todo 31: the internal JWKS listener holds its port and serves `GET /jwks` only.
    ///
    /// Another process can bind its port (named in the log) neither on `127.0.0.1` nor
    /// on `[::1]` (the second check is skipped, with the reason logged, on a host without
    /// `IPv6` loopback).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_internal_jwks_listener_holds_both_loopback_addresses() -> TestResult {
        let fixture = Fixture::new()?;
        let mut server = fixture.serve(Options::KCC)?;
        let line = server.wait_for("internal JWKS listener")?;
        let logged: Value = serde_json::from_str(&line)?;
        let port = logged
            .pointer("/fields/port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .ok_or_else(|| format!("no port: {line}"))?;
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        assert_eq!(
            TcpListener::bind(v4)
                .map(drop)
                .map_err(|error| error.kind()),
            Err(io::ErrorKind::AddrInUse)
        );
        match TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
            Ok(_ipv6) => {
                let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
                assert_eq!(
                    TcpListener::bind(v6)
                        .map(drop)
                        .map_err(|error| error.kind()),
                    Err(io::ErrorKind::AddrInUse)
                );
            }
            Err(error) => tracing::info!(%error, "live-skip: no IPv6 loopback on this host"),
        }
        let keys: Value = fixture
            .http()
            .get(format!("http://{v4}/jwks"))
            .send()
            .await?
            .json()
            .await?;
        assert_eq!(
            keys.pointer("/keys/0/alg").and_then(Value::as_str),
            Some("EdDSA")
        );
        for path in ["/oauth/jwks", "/", "/mcp"] {
            let other = fixture
                .http()
                .get(format!("http://{v4}{path}"))
                .send()
                .await?;
            assert_eq!(other.status(), StatusCode::NOT_FOUND, "{path}");
        }
        Ok(())
    }

    /// Todo 31: a TRACE log of the server and every file of its state directory hold none
    /// of the flow's consent request id, code, verifier, access and refresh tokens.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_secret_reaches_the_log_or_the_state() -> TestResult {
        let fixture = Fixture::new()?;
        let mut server = fixture.serve(Options {
            kcc: true,
            level: "trace",
        })?;
        let first = client(&fixture, &server).await?;
        let consent = begin(&fixture, &server, &first).await?;
        let browser = Browser::resume(&fixture, &server, ("alice", PASSWORD), &consent.id).await?;
        let approved = browser.decide(&fixture, &consent.id, "approve").await?;
        let target = hx_redirect(&approved).ok_or("no HX-Redirect")?;
        let code = param(&query(&target)?, "code").ok_or("no code")?.to_owned();
        let tokens = tokens_of(redeem(&fixture, &server, &consent, &code).await?, &first).await?;
        let session = Session::open(&fixture, &server, &tokens.access).await?;
        drop(session.tools(&fixture).await?);
        let rotated = tokens_of(
            refresh(&fixture, &server, (&first, &tokens.refresh)).await?,
            &first,
        )
        .await?;
        let revoked = tokens::revoke(&fixture, &server, (&first, &rotated.refresh)).await?;
        assert_eq!(revoked.status(), StatusCode::OK);
        let after = refresh(&fixture, &server, (&first, &rotated.refresh)).await?;
        assert_eq!(after.status(), StatusCode::BAD_REQUEST, "revoked");
        let log = server.log();
        assert!(
            log.contains("TRACE") || log.contains("\"level\":\"TRACE\""),
            "trace is on"
        );
        let state = String::from_utf8_lossy(&fixture.state_bytes()?).into_owned();
        for (name, secret) in [
            ("consent request id", consent.id.as_str()),
            ("code", code.as_str()),
            ("verifier", consent.pkce.verifier.as_str()),
            ("access", tokens.access.as_str()),
            ("refresh", tokens.refresh.as_str()),
            ("rotated access", rotated.access.as_str()),
            ("rotated refresh", rotated.refresh.as_str()),
        ] {
            assert!(!log.contains(secret), "{name} in the log");
            assert!(!state.contains(secret), "{name} in the state");
        }
        Ok(())
    }
}
