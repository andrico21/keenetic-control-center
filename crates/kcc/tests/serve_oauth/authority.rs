//! Todo 31 per-call authority: a kcc token carries no authority of its own; every call
//! reads the account and the grant again, so a change counts from the very next call.

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use core::time::Duration;
    use std::fs;

    use kcc_app::{
        accounts::{AccountChange, SystemClock, UsersDocument},
        mcp_auth::grants::GrantStore,
    };
    use reqwest::StatusCode;
    use secrecy::SecretString;
    use serde_json::{Value, json};

    use crate::{
        browser::{self, Browser},
        fixture::{Fixture, Options, PASSWORD, Server, TestResult},
        flow::{self, begin, client},
        mcp::{Session, ran, refused},
        tokens::{Tokens, error_of, redeem, refresh},
    };

    /// A read every role may call.
    const READ: (&str, fn() -> Value) = ("kcc_routers_list", || json!({}));

    /// A write tool of the core toolset (`Write`).
    const WRITE: (&str, fn() -> Value) = ("kcc_job_cancel", || json!({"job_id": "none"}));

    /// `account`'s tokens and an open session with them.
    async fn signed_in(
        fixture: &Fixture,
        server: &Server,
        account: &str,
    ) -> TestResult<(Tokens, Session)> {
        let tokens = flow::connect(fixture, server, account).await?;
        let session = Session::open(fixture, server, &tokens.access).await?;
        Ok((tokens, session))
    }

    /// Calls `tool` in `session`.
    async fn call(
        fixture: &Fixture,
        session: &Session,
        (name, arguments): (&str, fn() -> Value),
    ) -> TestResult<Value> {
        session.call(fixture, (name, arguments())).await
    }

    /// Todo 31: a role downgrade binds the very next call of an open session: the write
    /// tool the operator could call is refused, and the list loses it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_role_downgrade_refuses_the_next_write_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (_tokens, session) = signed_in(&fixture, &server, "olga").await?;
        assert!(
            ran(&call(&fixture, &session, WRITE).await?),
            "an operator may"
        );
        drop(
            fixture
                .accounts()?
                .administer("olga", &AccountChange::Role("viewer".to_owned()))?,
        );
        let answer = call(&fixture, &session, WRITE).await?;
        assert!(refused(&answer), "{answer}");
        let tools = session.tools(&fixture).await?;
        assert!(!tools.iter().any(|tool| tool == WRITE.0), "{tools:?}");
        assert!(ran(&call(&fixture, &session, READ).await?), "reads stay");
        Ok(())
    }

    /// Todo 31: a viewer's kcc token calling a write tool is refused by kcc's coarse gate
    /// (a protocol error, not a tool result), though the kit's role admits every tool.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_viewer_token_calling_a_write_tool_is_refused_by_the_coarse_gate() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (_tokens, session) = signed_in(&fixture, &server, "vera").await?;
        let answer = call(&fixture, &session, WRITE).await?;
        assert!(refused(&answer), "{answer}");
        assert!(ran(&call(&fixture, &session, READ).await?));
        Ok(())
    }

    /// One path of a sign-in in progress when the account changes.
    struct Paths {
        /// An open MCP session.
        session: Session,
        /// Its tokens.
        tokens: Tokens,
        /// A code approved but not redeemed yet, with its request.
        unredeemed: (flow::Consent, String),
        /// A browser on the consent page of a request not approved yet.
        open: (Browser, flow::Consent),
    }

    /// Every path of `account` that the change must refuse, prepared before it.
    async fn prepare(fixture: &Fixture, server: &Server, account: &str) -> TestResult<Paths> {
        let (tokens, session) = signed_in(fixture, server, account).await?;
        let first = client(fixture, server).await?;
        let approved = begin(fixture, server, &first).await?;
        let code = flow::approve(fixture, server, &approved, account).await?;
        let pending = begin(fixture, server, &first).await?;
        let browser = Browser::resume(fixture, server, (account, PASSWORD), &pending.id).await?;
        Ok(Paths {
            session,
            tokens,
            unredeemed: (approved, code),
            open: (browser, pending),
        })
    }

    /// Asserts that every path of `paths` is refused, and a new authorization request of
    /// `account` gets no consent page.
    async fn assert_refused(fixture: &Fixture, server: &Server, paths: Paths) -> TestResult {
        let answer = call(fixture, &paths.session, READ).await?;
        assert!(refused(&answer), "per call: {answer}");
        let renewed = refresh(
            fixture,
            server,
            (&paths.tokens.client, &paths.tokens.refresh),
        )
        .await?;
        assert_eq!(error_of(renewed).await?.1, "invalid_grant", "refresh");
        let (approved, code) = paths.unredeemed;
        let redeemed = redeem(fixture, server, &approved, &code).await?;
        assert_eq!(error_of(redeemed).await?.1, "invalid_grant", "token(code)");
        let (browser, pending) = paths.open;
        let decided = browser.decide(fixture, &pending.id, "approve").await?;
        let target = browser::hx_redirect(&decided).unwrap_or_default();
        assert!(!target.contains("code="), "approve: {target}");
        let next = begin(fixture, server, &pending.client).await?;
        let page = browser
            .get(fixture, &format!("/ui/oauth/consent?request={}", next.id))
            .await?
            .text()
            .await?;
        assert!(!page.contains("id=\"oauth-approve\""), "authorize: {page}");
        Ok(())
    }

    /// Todo 31: a disabled account is refused on every path: the next call, the refresh, a
    /// code approved before, an approval and a new consent page.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disabled_account_is_refused_on_every_path() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let paths = prepare(&fixture, &server, "dora").await?;
        drop(
            fixture
                .accounts()?
                .administer("dora", &AccountChange::Disabled(true))?,
        );
        assert_refused(&fixture, &server, paths).await
    }

    /// Todo 31: an account that must change its password is refused on every path, its
    /// password unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_account_that_must_change_its_password_is_refused_on_every_path() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let paths = prepare(&fixture, &server, "mira").await?;
        fixture.state()?.update(|document: &mut UsersDocument| {
            for account in &mut document.users {
                if account.username == "mira" {
                    account.must_change_password = true;
                }
            }
        })?;
        assert_refused(&fixture, &server, paths).await
    }

    /// Todo 31: a revoked grant, a grant deleted from the file and a changed password each
    /// refuse the very next call of an open session and the refresh.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn grant_and_password_changes_refuse_the_next_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (revoked, revoked_session) = signed_in(&fixture, &server, "alice").await?;
        let (deleted, deleted_session) = signed_in(&fixture, &server, "alice").await?;
        let (kept, kept_session) = signed_in(&fixture, &server, "alice").await?;
        let grants = fixture.grants()?;
        let id_of = |tokens: &Tokens| -> TestResult<String> {
            grants
                .grants()
                .iter()
                .find(|grant| grant.client() == tokens.client)
                .map(|grant| grant.id().to_owned())
                .ok_or_else(|| "no grant".into())
        };
        let store = GrantStore::new(
            fixture.state()?,
            Arc::new(SystemClock::default()),
            Duration::from_hours(1),
        );
        assert!(store.revoke(&id_of(&revoked)?)?);
        let path = fixture.state_dir().join("mcp_oauth_grants.json");
        let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let gone = id_of(&deleted)?;
        document
            .get_mut("grants")
            .and_then(Value::as_array_mut)
            .ok_or("grants")?
            .retain(|grant| grant.get("id").and_then(Value::as_str) != Some(gone.as_str()));
        fs::write(&path, serde_json::to_vec(&document)?)?;
        for (tokens, session) in [(&revoked, &revoked_session), (&deleted, &deleted_session)] {
            let answer = call(&fixture, session, READ).await?;
            assert!(refused(&answer), "{answer}");
            let renewed = refresh(&fixture, &server, (&tokens.client, &tokens.refresh)).await?;
            assert_eq!(error_of(renewed).await?.1, "invalid_grant");
        }
        assert!(
            ran(&call(&fixture, &kept_session, READ).await?),
            "other grants stay"
        );
        let new_password = SecretString::from("another horse battery staple");
        drop(fixture.accounts()?.change_password(
            "alice",
            &SecretString::from(PASSWORD),
            &new_password,
        )?);
        let answer = call(&fixture, &kept_session, READ).await?;
        assert!(refused(&answer), "{answer}");
        let renewed = refresh(&fixture, &server, (&kept.client, &kept.refresh)).await?;
        assert_eq!(error_of(renewed).await?.1, "invalid_grant");
        Ok(())
    }

    /// Todo 31: after a role edit on the Web (which rebuilds the kit's RBAC policy) a kcc
    /// token still opens sessions that list tools.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_role_edit_keeps_kcc_tokens_listing_tools() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let (tokens, _session) = signed_in(&fixture, &server, "alice").await?;
        let pending = begin(&fixture, &server, &tokens.client).await?;
        let web = Browser::resume(&fixture, &server, ("alice", PASSWORD), &pending.id).await?;
        let created = web
            .post(
                &fixture,
                "/ui/admin/roles",
                &[("name", "auditors"), ("scope", "*"), ("read", "on")],
            )
            .await?;
        assert_eq!(created.status(), StatusCode::OK);
        let roles = fs::read_to_string(fixture.state_dir().join("roles.json"))?;
        assert!(roles.contains("auditors"), "{roles}");
        let session = Session::open(&fixture, &server, &tokens.access).await?;
        let tools = session.tools(&fixture).await?;
        assert!(tools.iter().any(|tool| tool == READ.0), "{tools:?}");
        assert!(ran(&call(&fixture, &session, READ).await?));
        Ok(())
    }
}
