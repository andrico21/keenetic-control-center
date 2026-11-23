//! MCP over HTTP for the mTLS suite: a session signed in by the client certificate (no
//! `Authorization` header) or by an API key.

use reqwest::{Client, RequestBuilder, StatusCode, header};
use serde_json::{Value, json};

use crate::TestResult;

/// One MCP session at `url`.
pub(crate) struct Session<'client> {
    /// The HTTPS client (with or without a certificate).
    client: &'client Client,
    /// The server's base URL.
    url: String,
    /// The API key, when the session signs in with one.
    key: Option<String>,
    /// The `Mcp-Session-Id`.
    id: String,
}

impl<'client> Session<'client> {
    /// `initialize` and `notifications/initialized` at `url`.
    pub(crate) async fn open(
        client: &'client Client,
        url: &str,
        key: Option<&str>,
    ) -> TestResult<Self> {
        let mut session = Self {
            client,
            url: url.to_owned(),
            key: key.map(str::to_owned),
            id: String::new(),
        };
        let response = session
            .post(&json!({"jsonrpc":"2.0","id":1_u32,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mtls","version":"1"}}}))
            .send()
            .await?;
        if response.status() != StatusCode::OK {
            return Err(format!("initialize returned {}", response.status()).into());
        }
        session.id = response
            .headers()
            .get("mcp-session-id")
            .ok_or("no MCP session id")?
            .to_str()?
            .to_owned();
        let _accepted = session
            .post(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .send()
            .await?
            .error_for_status()?;
        Ok(session)
    }

    /// The names `tools/list` lists, sorted.
    pub(crate) async fn tool_names(&self) -> TestResult<Vec<String>> {
        let answer = self
            .call(&json!({"jsonrpc":"2.0","id":2_u32,"method":"tools/list","params":{}}))
            .await?;
        let mut names: Vec<String> = answer
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("no tools: {answer}"))?
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect();
        names.sort();
        Ok(names)
    }

    /// `tools/call` of `name` with `arguments`; the JSON-RPC answer.
    pub(crate) async fn call_tool(&self, name: &str, arguments: Value) -> TestResult<Value> {
        self.call(&json!({"jsonrpc":"2.0","id":3_u32,"method":"tools/call","params":{"name":name,"arguments":arguments}}))
            .await
    }

    /// Posts `message` and parses the answer (plain JSON or the first SSE `data:` line).
    async fn call(&self, message: &Value) -> TestResult<Value> {
        let body = self
            .post(message)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let payload = body
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .find(|data| !data.is_empty())
            .unwrap_or(body.as_str());
        Ok(serde_json::from_str(payload)?)
    }

    /// A POST of `message` to `/mcp`, with the session id once there is one and the API
    /// key when the session has one.
    fn post(&self, message: &Value) -> RequestBuilder {
        let mut request = self
            .client
            .post(format!("{}/mcp", self.url))
            .header(header::ACCEPT, "application/json, text/event-stream")
            .json(message);
        if !self.id.is_empty() {
            request = request.header("Mcp-Session-Id", &self.id);
        }
        match &self.key {
            Some(key) => request.bearer_auth(key),
            None => request,
        }
    }
}
