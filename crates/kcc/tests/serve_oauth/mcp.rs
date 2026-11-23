//! An MCP client over Streamable HTTP with a bearer token: a session, tool calls and
//! the tool list.
#![expect(
    clippy::missing_errors_doc,
    reason = "test support returns the boxed error of whatever step failed"
)]

use reqwest::{Response, StatusCode, header};
use serde_json::{Value, json};

use crate::fixture::{Fixture, Server, TestResult};

/// One MCP session opened with a bearer token.
pub(crate) struct Session {
    /// The `/mcp` URL.
    url: String,
    /// The bearer token.
    token: String,
    /// The session id.
    id: String,
}

/// `body`'s JSON-RPC message: the body itself, or the last `data:` line of an event
/// stream.
pub(crate) fn message(body: &str) -> TestResult<Value> {
    let data = body
        .lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .rfind(|line| !line.is_empty());
    Ok(serde_json::from_str(data.unwrap_or(body))?)
}

/// `POST /mcp` with `token` (and `session`), carrying `body`.
pub(crate) async fn post(
    fixture: &Fixture,
    (url, token, session): (&str, &str, Option<&str>),
    body: &Value,
) -> TestResult<Response> {
    let mut request = fixture
        .http()
        .post(url)
        .bearer_auth(token)
        .header(header::ACCEPT, "application/json, text/event-stream")
        .json(body);
    if let Some(id) = session {
        request = request.header("Mcp-Session-Id", id);
    }
    Ok(request.send().await?)
}

/// The status of an `initialize` with `token`.
pub(crate) async fn initialize_status(
    fixture: &Fixture,
    server: &Server,
    token: &str,
) -> TestResult<StatusCode> {
    Ok(
        post(fixture, (&server.resource(), token, None), &initialize())
            .await?
            .status(),
    )
}

/// The `initialize` request.
fn initialize() -> Value {
    json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"oauth","version":"1"}}})
}

impl Session {
    /// Opens a session with `token`.
    pub(crate) async fn open(fixture: &Fixture, server: &Server, token: &str) -> TestResult<Self> {
        let url = server.resource();
        let opened = post(fixture, (&url, token, None), &initialize()).await?;
        if opened.status() != StatusCode::OK {
            return Err(format!("initialize answered {}", opened.status()).into());
        }
        let id = opened
            .headers()
            .get("mcp-session-id")
            .ok_or("no MCP session id")?
            .to_str()?
            .to_owned();
        let session = Self {
            url,
            token: token.to_owned(),
            id,
        };
        let initialized = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        drop(
            post(
                fixture,
                (&session.url, &session.token, Some(&session.id)),
                &initialized,
            )
            .await?,
        );
        Ok(session)
    }

    /// The JSON-RPC answer to `method` with `params`.
    pub(crate) async fn request(
        &self,
        fixture: &Fixture,
        (method, params): (&str, Value),
    ) -> TestResult<Value> {
        let body = json!({"jsonrpc":"2.0","id":7_u32,"method":method,"params":params});
        let answer = post(fixture, (&self.url, &self.token, Some(&self.id)), &body).await?;
        let status = answer.status();
        let text = answer.text().await?;
        if status != StatusCode::OK {
            return Err(format!("{method} answered {status}: {text}").into());
        }
        message(&text)
    }

    /// The names of the listed tools.
    pub(crate) async fn tools(&self, fixture: &Fixture) -> TestResult<Vec<String>> {
        let answer = self.request(fixture, ("tools/list", json!({}))).await?;
        let tools = answer
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("tools/list answered {answer}"))?;
        Ok(tools
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect())
    }

    /// The JSON-RPC answer to calling `name` with `arguments`.
    pub(crate) async fn call(
        &self,
        fixture: &Fixture,
        (name, arguments): (&str, Value),
    ) -> TestResult<Value> {
        self.request(
            fixture,
            ("tools/call", json!({"name": name, "arguments": arguments})),
        )
        .await
    }
}

/// Whether `answer` is kcc's refusal of the caller: a JSON-RPC error `forbidden`, not a
/// tool result.
pub(crate) fn refused(answer: &Value) -> bool {
    answer.get("result").is_none()
        && answer.pointer("/error/message").and_then(Value::as_str) == Some("forbidden")
}

/// Whether `answer` is a tool result (the tool ran, whatever it concluded).
pub(crate) fn ran(answer: &Value) -> bool {
    answer.get("result").is_some()
}
