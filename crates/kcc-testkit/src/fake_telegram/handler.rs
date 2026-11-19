//! The `sendMessage` handler of the fake Telegram Bot API.

use alloc::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse as _, Response},
};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep};

use super::{Fault, Request, Shared};

/// Longest text, in UTF-16 code units, that kcc sends and the fake accepts.
const MAX_TEXT_UNITS: usize = 4096;

/// An error reply in the Bot API shape.
fn failure(status: StatusCode, description: &str, parameters: Option<Value>) -> Response {
    let mut body = json!({
        "ok": false,
        "error_code": status.as_u16(),
        "description": description,
    });
    if let (Some(extra), Some(object)) = (parameters, body.as_object_mut()) {
        drop(object.insert("parameters".to_owned(), extra));
    }
    (status, Json(body)).into_response()
}

/// The reply a fault stands for; `None` for a delay, which ends in a normal answer.
fn fault_reply(fault: Fault) -> Option<Response> {
    match fault {
        Fault::TooManyRequests { retry_after } => Some(failure(
            StatusCode::TOO_MANY_REQUESTS,
            &format!("Too Many Requests: retry after {retry_after}"),
            Some(json!({"retry_after": retry_after})),
        )),
        Fault::Unauthorized => Some(failure(StatusCode::UNAUTHORIZED, "Unauthorized", None)),
        Fault::Forbidden => Some(failure(
            StatusCode::FORBIDDEN,
            "Forbidden: bot was blocked by the user",
            None,
        )),
        Fault::ChatNotFound => Some(failure(
            StatusCode::BAD_REQUEST,
            "Bad Request: chat not found",
            None,
        )),
        Fault::InternalServerError => Some(failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            None,
        )),
        Fault::Redirect(location) => Some(match HeaderValue::from_str(&location) {
            Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
            Err(_invalid) => StatusCode::BAD_GATEWAY.into_response(),
        }),
        Fault::Slow(_) => None,
    }
}

/// Handles `sendMessage`: records the request, then applies the token check, the next
/// matching fault and the content rules.
// NOT cancel-safe: cancellation during a configured delay consumes that fault.
pub(super) async fn send_message(
    State(shared): State<Arc<Shared>>,
    Path(bot): Path<String>,
    raw: Bytes,
) -> Response {
    let at = Instant::now();
    let Some(token) = bot.strip_prefix("bot") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
    let chat_id = body.get("chat_id").cloned().unwrap_or(Value::Null);
    let text = body
        .get("text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let fault = {
        let mut state = shared.lock();
        let authorized = state
            .expected
            .as_deref()
            .is_none_or(|wanted| wanted == token);
        state.requests.push(Request {
            token: token.to_owned(),
            chat_id: chat_id.clone(),
            text: text.clone(),
            body,
            at,
        });
        let captured = state.requests.len();
        let fault = if authorized {
            let position = state
                .faults
                .iter()
                .position(|(scope, _fault)| scope.as_ref().is_none_or(|chat| *chat == chat_id));
            position.map(|index| state.faults.remove(index).1)
        } else {
            Some(Fault::Unauthorized)
        };
        drop(state);
        let _previous: usize = shared.count.send_replace(captured);
        fault
    };
    match fault {
        Some(Fault::Slow(delay)) => sleep(delay).await,
        Some(other) => {
            if let Some(reply) = fault_reply(other) {
                return reply;
            }
        }
        None => {}
    }
    if chat_id.is_null() {
        return failure(
            StatusCode::BAD_REQUEST,
            "Bad Request: chat_id is empty",
            None,
        );
    }
    if text.is_empty() {
        return failure(
            StatusCode::BAD_REQUEST,
            "Bad Request: message text is empty",
            None,
        );
    }
    if text.encode_utf16().count() > MAX_TEXT_UNITS {
        return failure(
            StatusCode::BAD_REQUEST,
            "Bad Request: message is too long",
            None,
        );
    }
    let message_id = {
        let mut state = shared.lock();
        let id = state.next_id;
        state.next_id = id.saturating_add(1);
        id
    };
    Json(json!({
        "ok": true,
        "result": {"message_id": message_id, "chat": {"id": chat_id}, "text": text},
    }))
    .into_response()
}
