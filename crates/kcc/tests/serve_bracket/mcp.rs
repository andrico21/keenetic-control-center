//! An MCP client of the served `kcc serve`: sessions that send, or abandon, a raw CLI line.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use reqwest::{Client, Response, header};
use serde_json::{Value, json};

use crate::support::TestResult;

/// The JSON-RPC request `body` sent to `/mcp` with `key` and `session`.
async fn rpc(
    client: &Client,
    (base, key, session): (&str, &str, Option<&str>),
    body: &Value,
) -> TestResult<Response> {
    let mut request = client
        .post(format!("{base}/mcp"))
        .bearer_auth(key)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .json(body);
    if let Some(id) = session {
        request = request.header("Mcp-Session-Id", id);
    }
    Ok(request.send().await?.error_for_status()?)
}

/// Opens a session with `key`; returns its id.
pub(crate) async fn open(client: &Client, (base, key): (&str, &str)) -> TestResult<String> {
    let opened = rpc(
        client,
        (base, key, None),
        &json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"bracket","version":"1"}}}),
    )
    .await?;
    let session = opened
        .headers()
        .get("mcp-session-id")
        .ok_or("no MCP session id")?
        .to_str()?
        .to_owned();
    drop(
        rpc(
            client,
            (base, key, Some(&session)),
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await?,
    );
    Ok(session)
}

/// The `tools/call` request, id 2, that sends `line`, confirmed, through `kcc_cli_parse`.
pub(crate) fn cli_call(line: &str) -> Value {
    json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/call","params":{"name":"kcc_cli_parse","arguments":{"host":"router","line":line,"confirm":true}}})
}

/// Opens a session with `key` and sends `line`, confirmed, through `kcc_cli_parse` to
/// the router; the call's response once its headers arrive.
pub(crate) async fn cli_parse(
    client: &Client,
    (base, key): (&str, &str),
    line: &str,
) -> TestResult<Response> {
    let session = open(client, (base, key)).await?;
    rpc(client, (base, key, Some(&session)), &cli_call(line)).await
}

/// Tells the server that the client of `session` abandoned the call with id 2.
pub(crate) async fn cancel(
    client: &Client,
    (base, key, session): (&str, &str, &str),
) -> TestResult {
    drop(
        rpc(
            client,
            (base, key, Some(session)),
            &json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2_u32,"reason":"client gone"}}),
        )
        .await?,
    );
    Ok(())
}
