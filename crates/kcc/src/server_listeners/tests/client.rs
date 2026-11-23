//! HTTP clients of the listeners: health, Web sign-in, MCP sessions.

use core::{net::SocketAddr, time::Duration};

use reqwest::{Client, Response, StatusCode, header, redirect::Policy};
use rustls::crypto::ring::default_provider;
use serde_json::{Value, json};

use super::{TestResult, fixture::PASSWORD};

/// A client that follows no redirect, with a bounded timeout.
///
/// It keeps no idle connection: every request opens its own, so none rides a keep-alive
/// connection of a listener generation a restart has since closed (which resets it). The
/// cookies and keys go in headers, so sessions do not depend on the connection.
pub(super) fn http() -> TestResult<Client> {
    let _installed = default_provider().install_default();
    Ok(Client::builder()
        .redirect(Policy::none())
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(10))
        .build()?)
}

/// The status of `GET path` at `address`.
pub(super) async fn status(
    client: &Client,
    address: SocketAddr,
    path: &str,
) -> TestResult<StatusCode> {
    Ok(client
        .get(format!("http://{address}{path}"))
        .send()
        .await?
        .status())
}

/// The body of `GET path` at `address`.
pub(super) async fn text(client: &Client, address: SocketAddr, path: &str) -> TestResult<String> {
    Ok(client
        .get(format!("http://{address}{path}"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

/// The `name=value` pair of `response`'s `Set-Cookie`.
fn cookie(response: &Response) -> TestResult<String> {
    Ok(response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .ok_or("missing Set-Cookie")?
        .to_owned())
}

/// Signs `alice` in at `address`; her session cookie.
pub(super) async fn sign_in(client: &Client, address: SocketAddr) -> TestResult<String> {
    let base = format!("http://{address}");
    let login = client.get(format!("{base}/ui/login")).send().await?;
    let anonymous = cookie(&login)?;
    let page = login.text().await?;
    let csrf = page
        .split_once("<meta name=\"csrf-token\" content=\"")
        .and_then(|(_, tail)| tail.split_once('"'))
        .map(|(token, _)| token.to_owned())
        .ok_or("no CSRF token")?;
    let response = client
        .post(format!("{base}/ui/login"))
        .header(header::COOKIE, anonymous)
        .header(header::ORIGIN, &base)
        .header("sec-fetch-site", "same-origin")
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(format!(
            "username=alice&password={}",
            PASSWORD.replace(' ', "+")
        ))
        .send()
        .await?;
    if response.status() != StatusCode::SEE_OTHER {
        return Err(format!("sign-in answered {}", response.status()).into());
    }
    cookie(&response)
}

/// The status of `/ui/account` with `session`.
pub(super) async fn account(
    client: &Client,
    address: SocketAddr,
    session: &str,
) -> TestResult<StatusCode> {
    Ok(client
        .get(format!("http://{address}/ui/account"))
        .header(header::COOKIE, session)
        .send()
        .await?
        .status())
}

/// One MCP request at `address` with `key`, in `session` when set.
async fn mcp(
    client: &Client,
    (address, key): (SocketAddr, &str),
    session: Option<&str>,
    body: &Value,
) -> TestResult<Response> {
    let mut request = client
        .post(format!("http://{address}/mcp"))
        .bearer_auth(key)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .json(body);
    if let Some(id) = session {
        request = request.header("Mcp-Session-Id", id);
    }
    Ok(request.send().await?)
}

/// The JSON-RPC message of an MCP response body (plain JSON or one SSE event).
async fn message(response: Response) -> TestResult<Value> {
    let body = response.error_for_status()?.text().await?;
    let payload = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim_start)
        .find(|payload| !payload.is_empty())
        .unwrap_or(body.as_str());
    Ok(serde_json::from_str(payload)?)
}

/// The status of an MCP `initialize` with `key`.
pub(super) async fn initialize_status(
    client: &Client,
    address: SocketAddr,
    key: &str,
) -> TestResult<StatusCode> {
    Ok(mcp(client, (address, key), None, &initialize())
        .await?
        .status())
}

/// The `initialize` request.
fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"supervisor","version":"1"}}})
}

/// An initialized MCP session at `address` with `key`.
pub(super) async fn session(client: &Client, address: SocketAddr, key: &str) -> TestResult<String> {
    let response = mcp(client, (address, key), None, &initialize()).await?;
    let id = response
        .headers()
        .get("mcp-session-id")
        .ok_or("no MCP session id")?
        .to_str()?
        .to_owned();
    drop(message(response).await?);
    drop(
        mcp(
            client,
            (address, key),
            Some(&id),
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await?
        .error_for_status()?,
    );
    Ok(id)
}

/// The tool names `tools/list` returns in `session`.
pub(super) async fn tools(
    client: &Client,
    (address, key): (SocketAddr, &str),
    session: &str,
) -> TestResult<Vec<String>> {
    let reply = message(
        mcp(
            client,
            (address, key),
            Some(session),
            &json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/list","params":{}}),
        )
        .await?,
    )
    .await?;
    Ok(reply
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .ok_or("no tools")?
        .iter()
        .filter_map(|tool| tool.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect())
}

/// The `error` code of a `tools/call` of `kcc_rci_delete` (a destructive raw tool) in
/// `session`.
pub(super) async fn delete_error(
    client: &Client,
    (address, key): (SocketAddr, &str),
    session: &str,
) -> TestResult<String> {
    let reply = message(
        mcp(
            client,
            (address, key),
            Some(session),
            &json!({"jsonrpc":"2.0","id":3_u32,"method":"tools/call","params":{"name":"kcc_rci_delete","arguments":{
                "host":"absent","catalog_path":"ip hotspot host","path":["ip","hotspot","host"],
                "value":{"mac":"02:00:00:00:11:01"},"confirm":true}}}),
        )
        .await?,
    )
    .await?;
    let text = reply
        .pointer("/result/content/0/text")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no tool result: {reply}"))?;
    Ok(serde_json::from_str::<Value>(text)?
        .get("error")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no error code: {text}"))?
        .to_owned())
}
