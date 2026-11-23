//! Todo 31 per-call authority after a deletion: a deleted account or client refuses the
//! very next call of an open session and the refresh.

#[cfg(test)]
mod tests {
    use std::fs;

    use kcc_app::accounts::AccountChange;
    use serde_json::{Value, json};

    use crate::{
        fixture::{Fixture, Options, TestResult},
        flow,
        mcp::{Session, ran, refused},
        tokens::{error_of, refresh},
    };

    /// A read every role may call.
    const READ: (&str, fn() -> Value) = ("kcc_routers_list", || json!({}));

    /// Todo 31 (P8): deleting the account of an open kcc session refuses its next call
    /// and its refresh (`invalid_grant`); another account's session still runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deleted_account_refuses_the_next_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let gone = flow::connect(&fixture, &server, "dora").await?;
        let gone_session = Session::open(&fixture, &server, &gone.access).await?;
        let kept = flow::connect(&fixture, &server, "olga").await?;
        let kept_session = Session::open(&fixture, &server, &kept.access).await?;
        assert!(ran(&gone_session
            .call(&fixture, (READ.0, READ.1()))
            .await?));
        drop(
            fixture
                .accounts()?
                .administer("dora", &AccountChange::Delete)?,
        );
        let answer = gone_session.call(&fixture, (READ.0, READ.1())).await?;
        assert!(refused(&answer), "{answer}");
        let renewed = refresh(&fixture, &server, (&gone.client, &gone.refresh)).await?;
        assert_eq!(error_of(renewed).await?.1, "invalid_grant");
        assert!(
            ran(&kept_session.call(&fixture, (READ.0, READ.1())).await?),
            "other accounts stay"
        );
        Ok(())
    }

    /// Todo 31 (client deletion): removing a client from `mcp_oauth_clients.json` refuses
    /// the next call of its open session and its refresh; another client's session still
    /// runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_deleted_client_refuses_the_next_call() -> TestResult {
        let fixture = Fixture::new()?;
        let server = fixture.serve(Options::KCC)?;
        let gone = flow::connect(&fixture, &server, "alice").await?;
        let gone_session = Session::open(&fixture, &server, &gone.access).await?;
        let kept = flow::connect(&fixture, &server, "alice").await?;
        let kept_session = Session::open(&fixture, &server, &kept.access).await?;
        assert!(ran(&gone_session
            .call(&fixture, (READ.0, READ.1()))
            .await?));
        let path = fixture.state_dir().join("mcp_oauth_clients.json");
        let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let clients = document
            .get_mut("clients")
            .and_then(Value::as_array_mut)
            .ok_or("clients")?;
        let before = clients.len();
        clients.retain(|client| client.get("id").and_then(Value::as_str) != Some(&gone.client));
        assert_eq!(
            clients.len().saturating_add(1),
            before,
            "one client removed"
        );
        fs::write(&path, serde_json::to_vec(&document)?)?;
        let answer = gone_session.call(&fixture, (READ.0, READ.1())).await?;
        assert!(refused(&answer), "{answer}");
        let renewed = refresh(&fixture, &server, (&gone.client, &gone.refresh)).await?;
        let error = error_of(renewed).await?.1;
        assert!(
            error == "invalid_client" || error == "invalid_grant",
            "refresh: {error}"
        );
        assert!(
            ran(&kept_session.call(&fixture, (READ.0, READ.1())).await?),
            "other clients stay"
        );
        Ok(())
    }
}
