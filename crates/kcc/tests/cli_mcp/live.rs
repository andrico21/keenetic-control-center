//! A revocation or a client deletion reaches a running `kcc serve` at the next MCP call.
//!
//! The very next call of an open session is refused: the per-call check reads the grants again, and the
//! OAuth endpoints read the clients file on every request.

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;
    use serde_json::{Value, json};

    use crate::{
        browser::Browser,
        fixture::{Fixture, Options, PASSWORD, Server, TestResult},
        flow::{self, REDIRECT, authorize, begin},
        mcp::{Session, ran, refused},
        run::{code, config, kcc, stderr},
        tokens::{Tokens, error_of, refresh},
    };

    /// A read every role may call.
    const READ: (&str, fn() -> Value) = ("kcc_routers_list", || json!({}));

    /// `account`'s tokens, an open session with them that just ran a call, and the id of
    /// the one live grant `account` holds.
    async fn connected(
        fixture: &Fixture,
        server: &Server,
        account: &str,
    ) -> TestResult<(Tokens, Session, String)> {
        let tokens = flow::connect(fixture, server, account).await?;
        let session = Session::open(fixture, server, &tokens.access).await?;
        let first = session.call(fixture, (READ.0, (READ.1)())).await?;
        assert!(ran(&first), "the session works: {first}");
        let grants = fixture.grants()?;
        let held = grants
            .grants()
            .iter()
            .filter(|grant| grant.account() == account && !grant.is_revoked())
            .collect::<Vec<_>>();
        let [grant] = held.as_slice() else {
            return Err(format!("one grant of {account}").into());
        };
        Ok((tokens, session, grant.id().to_owned()))
    }

    /// Open sessions of `olga` and `vera`, olga's grant id, and alice signed in on the Web.
    ///
    /// The test revokes olga's grant; vera's session must keep working.
    async fn two_sessions(
        fixture: &Fixture,
        server: &Server,
    ) -> TestResult<(Session, Session, String, Browser)> {
        let (tokens, olga, grant) = connected(fixture, server, "olga").await?;
        let (_vera_tokens, vera, _vera_grant) = connected(fixture, server, "vera").await?;
        let consent = begin(fixture, server, &tokens.client).await?;
        let admin = Browser::resume(fixture, server, ("alice", PASSWORD), &consent.id).await?;
        Ok((olga, vera, grant, admin))
    }

    /// Asserts the very next call of `revoked` is refused and that of `unrelated` runs.
    async fn next_calls(fixture: &Fixture, revoked: &Session, unrelated: &Session) -> TestResult {
        let next = revoked.call(fixture, (READ.0, (READ.1)())).await?;
        assert!(refused(&next), "the very next call is refused: {next}");
        let other = unrelated.call(fixture, (READ.0, (READ.1)())).await?;
        assert!(ran(&other), "an unrelated session keeps working: {other}");
        Ok(())
    }

    /// Regression (todo 32): a Web revoke refuses the next call of the session.
    ///
    /// Revoking one grant on the Web connections tab of the running server makes it refuse
    /// the very next call of that session; another account's open session keeps working.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_web_revoke_refuses_the_next_mcp_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (olga, vera, grant, admin) = two_sessions(&fixture, &server).await?;
        let path = format!("/ui/admin/mcp/connections/revoke?grant={grant}");
        let revoked = admin.post(&fixture, &path, &[("confirm", "yes")]).await?;
        assert_eq!(revoked.status(), StatusCode::OK);
        next_calls(&fixture, &olga, &vera).await
    }

    /// Regression (todo 32): a Web account revoke refuses the next call of the session.
    ///
    /// Revoking every grant of an account on the Web connections tab of the running server
    /// makes it refuse the very next call of that account's session; another account's
    /// open session keeps working.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_web_account_revoke_refuses_the_next_mcp_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (olga, vera, _grant, admin) = two_sessions(&fixture, &server).await?;
        let typed = [
            ("confirm", "yes"),
            ("object", "olga"),
            ("confirm_name", "olga"),
        ];
        let path = "/ui/admin/mcp/connections/revoke-account?account=olga";
        let revoked = admin.post(&fixture, path, &typed).await?;
        assert_eq!(revoked.status(), StatusCode::OK);
        next_calls(&fixture, &olga, &vera).await
    }

    /// Regression (todo 32): a CLI account revoke refuses the next call of the session.
    ///
    /// `kcc mcp connections revoke-account` makes the running server refuse the very next
    /// call of that account's session; another account's open session keeps working.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cli_account_revoke_refuses_the_next_mcp_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (_tokens, olga, _grant) = connected(&fixture, &server, "olga").await?;
        let (_vera_tokens, vera, _vera_grant) = connected(&fixture, &server, "vera").await?;
        let cli = config(&fixture, "admin", "")?;
        let args = [
            "mcp",
            "connections",
            "revoke-account",
            "olga",
            "--confirm-destructive",
            "olga",
        ];
        let revoked = kcc(&fixture, &cli, &args, &[])?;
        assert_eq!(code(&revoked), Some(0_i32), "{}", stderr(&revoked));
        next_calls(&fixture, &olga, &vera).await
    }

    /// Regression (todo 32): `kcc mcp connections revoke` makes the running server refuse
    /// the very next call of the open session, and the refresh token is dead.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cli_revoke_refuses_the_next_mcp_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (tokens, session, grant) = connected(&fixture, &server, "olga").await?;
        let cli = config(&fixture, "admin", "")?;
        let args = [
            "mcp",
            "connections",
            "revoke",
            &grant,
            "--confirm-destructive",
            &grant,
        ];
        let revoked = kcc(&fixture, &cli, &args, &[])?;
        assert_eq!(code(&revoked), Some(0_i32), "{}", stderr(&revoked));
        let next = session.call(&fixture, (READ.0, (READ.1)())).await?;
        assert!(refused(&next), "the very next call is refused: {next}");
        let (status, error) =
            error_of(refresh(&fixture, &server, (&tokens.client, &tokens.refresh)).await?).await?;
        assert_eq!(
            (status, error.as_str()),
            (StatusCode::BAD_REQUEST, "invalid_grant")
        );
        Ok(())
    }

    /// Regression (todo 32): `kcc mcp clients delete` refuses the next call of a session.
    ///
    /// It revokes the client's grants with it, so the running server refuses the very next call of the open session; the client
    /// is unknown to the token and authorization endpoints at once (they read the clients
    /// file on every request).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cli_client_delete_refuses_the_next_mcp_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (tokens, session, _grant) = connected(&fixture, &server, "olga").await?;
        let cli = config(&fixture, "admin", "")?;
        let client = tokens.client.clone();
        let args = [
            "mcp",
            "clients",
            "delete",
            &client,
            "--confirm-destructive",
            &client,
        ];
        let deleted = kcc(&fixture, &cli, &args, &[])?;
        assert_eq!(code(&deleted), Some(0_i32), "{}", stderr(&deleted));
        let next = session.call(&fixture, (READ.0, (READ.1)())).await?;
        assert!(refused(&next), "the very next call is refused: {next}");
        let (status, error) =
            error_of(refresh(&fixture, &server, (&client, &tokens.refresh)).await?).await?;
        assert_eq!(
            (status, error.as_str()),
            (StatusCode::UNAUTHORIZED, "invalid_client")
        );
        let resource = server.resource();
        let answer = authorize(
            &fixture,
            &server,
            &[
                ("response_type", "code"),
                ("client_id", &client),
                ("redirect_uri", REDIRECT),
                ("code_challenge", &"a".repeat(43)),
                ("code_challenge_method", "S256"),
                ("resource", &resource),
            ],
        )
        .await?;
        assert_eq!(
            answer.status(),
            StatusCode::BAD_REQUEST,
            "an unknown client"
        );
        assert!(
            answer.headers().get("location").is_none(),
            "never redirected"
        );
        Ok(())
    }

    /// Regression (todo 32): deleting the client on the Web connections tab of the running
    /// server revokes its grants with it, so the very next call of the open session is
    /// refused.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_web_client_delete_refuses_the_next_mcp_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (tokens, session, grant) = connected(&fixture, &server, "olga").await?;
        let consent = begin(&fixture, &server, &tokens.client).await?;
        let admin = Browser::resume(&fixture, &server, ("alice", PASSWORD), &consent.id).await?;
        let tab = admin.get(&fixture, "/ui/admin/mcp/connections").await?;
        assert_eq!(tab.status(), StatusCode::OK);
        assert!(
            tab.text().await?.contains(&format!("revoke?grant={grant}")),
            "listed"
        );
        let path = format!("/ui/admin/mcp/clients/delete?client={}", tokens.client);
        let deleted = admin.post(&fixture, &path, &[("confirm", "yes")]).await?;
        assert_eq!(deleted.status(), StatusCode::OK);
        let next = session.call(&fixture, (READ.0, (READ.1)())).await?;
        assert!(refused(&next), "the very next call is refused: {next}");
        Ok(())
    }
}
