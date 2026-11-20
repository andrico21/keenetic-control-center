//! Public HTTP tests for the fake Telegram Bot API.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, time::Duration};

    use kcc_testkit::fake_telegram::{FakeTelegram, Fault};
    use serde_json::{Value, json};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
        time::timeout,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    /// One reply: status, lower-cased header block, JSON body (`null` when empty).
    struct Reply {
        status: u16,
        head: String,
        body: Value,
    }

    /// A numeric chat id.
    fn chat(id: i64) -> Value {
        Value::from(id)
    }

    /// A dummy bot token built at run time.
    fn token() -> String {
        format!("{}:{}", 4242, "k".repeat(35))
    }

    /// Posts `body` to `path` on the fake at `url` over a fresh connection.
    // NOT cancel-safe: a dropped request leaves a half-written connection.
    async fn post(url: &str, path: &str, body: &Value) -> TestResult<Reply> {
        exchange("POST", url, path, body).await
    }

    /// Puts `body` to `path` on the fake at `url` over a fresh connection.
    // NOT cancel-safe: see `post`.
    async fn put(url: &str, path: &str, body: &Value) -> TestResult<Reply> {
        exchange("PUT", url, path, body).await
    }

    /// Sends one `method` request with a JSON `body` and reads the whole reply.
    // NOT cancel-safe: a dropped request leaves a half-written connection.
    async fn exchange(method: &str, url: &str, path: &str, body: &Value) -> TestResult<Reply> {
        let host = url.strip_prefix("http://").ok_or("not an http url")?;
        let payload = serde_json::to_vec(body)?;
        let mut stream = TcpStream::connect(host).await?;
        let request_head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        stream.write_all(request_head.as_bytes()).await?;
        stream.write_all(&payload).await?;
        let mut raw = Vec::new();
        let _read: usize = stream.read_to_end(&mut raw).await?;
        let text = String::from_utf8(raw)?;
        let (header_block, payload_text) = text.split_once("\r\n\r\n").ok_or("no header block")?;
        let status = header_block
            .split_whitespace()
            .nth(1)
            .ok_or("no status")?
            .parse::<u16>()?;
        let parsed = if payload_text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(payload_text)?
        };
        Ok(Reply {
            status,
            head: header_block.to_ascii_lowercase(),
            body: parsed,
        })
    }

    /// Sends `text` to `chat` as the bot `token`.
    // NOT cancel-safe: see `post`.
    async fn send(fake: &FakeTelegram, token: &str, chat: &Value, text: &str) -> TestResult<Reply> {
        let path = format!("/bot{token}/sendMessage");
        post(&fake.url(), &path, &json!({"chat_id": chat, "text": text})).await
    }

    /// A success reply has the Bot API shape and the request is recorded with its token.
    // NOT cancel-safe: owns a fake Telegram task.
    #[tokio::test]
    async fn success_reply_has_the_bot_api_shape() -> TestResult {
        let fake = FakeTelegram::spawn().await?;
        let token = token();
        fake.expect_token(&token);
        let reply = send(&fake, &token, &chat(-1001), "hello").await?;
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.body,
            json!({"ok": true, "result": {"message_id": 1_u64, "chat": {"id": -1001_i64}, "text": "hello"}})
        );
        let seen = fake.requests();
        assert_eq!(seen.len(), 1);
        let first = seen.first().ok_or("no request")?;
        assert_eq!(first.token(), token);
        assert_eq!(first.chat_id(), &chat(-1001));
        assert_eq!(first.text(), "hello");
        assert_eq!(
            first.body(),
            &json!({"chat_id": -1001_i64, "text": "hello"})
        );
        fake.shutdown().await?;
        Ok(())
    }

    /// Any other token gets 401, and unknown paths get 404.
    // NOT cancel-safe: owns a fake Telegram task.
    #[tokio::test]
    async fn wrong_token_is_unauthorized_and_other_paths_are_not_found() -> TestResult {
        let fake = FakeTelegram::spawn().await?;
        fake.expect_token(&token());
        let reply = send(
            &fake,
            &format!("{}:{}", 1_u8, "z".repeat(35)),
            &chat(1),
            "x",
        )
        .await?;
        assert_eq!(reply.status, 401);
        assert_eq!(reply.body.get("error_code"), Some(&json!(401_u16)));
        let missing = post(&fake.url(), "/bot1/other", &json!({})).await?;
        assert_eq!(missing.status, 404);
        fake.shutdown().await?;
        Ok(())
    }

    /// ci fix: refused requests are drained before the 404/405.
    ///
    /// Closing the connection with unread request bytes resets a client that is still
    /// writing a body larger than the socket buffers.
    // NOT cancel-safe: owns a fake Telegram task.
    #[tokio::test]
    async fn refused_requests_with_a_large_body_still_get_a_complete_reply() -> TestResult {
        let fake = FakeTelegram::spawn().await?;
        let padding = "x".repeat(1024 * 1024);
        let body = json!({ "pad": padding });
        let missing = timeout(
            Duration::from_secs(30),
            post(&fake.url(), "/bot1/other", &body),
        )
        .await??;
        assert_eq!(missing.status, 404);
        let wrong_method = timeout(
            Duration::from_secs(30),
            put(&fake.url(), "/bot1/sendMessage", &body),
        )
        .await??;
        assert_eq!(wrong_method.status, 405);
        fake.shutdown().await?;
        Ok(())
    }

    /// Each fault answers the next request once, in order, then the replies succeed.
    // NOT cancel-safe: owns a fake Telegram task.
    #[tokio::test]
    async fn faults_are_consumed_in_order_then_success() -> TestResult {
        let fake = FakeTelegram::spawn().await?;
        let token = token();
        let target = format!("{}/target", fake.url());
        let faults = [
            (Fault::TooManyRequests { retry_after: 7 }, 429),
            (Fault::Unauthorized, 401),
            (Fault::Forbidden, 403),
            (Fault::ChatNotFound, 400),
            (Fault::InternalServerError, 500),
            (Fault::Redirect(target.clone()), 302),
            (Fault::Slow(Duration::from_millis(1)), 200),
        ];
        for (fault, _status) in &faults {
            fake.push_fault(fault.clone());
        }
        for (_fault, status) in &faults {
            let reply = send(&fake, &token, &chat(5), "x").await?;
            assert_eq!(reply.status, *status);
            if *status == 429 {
                assert_eq!(
                    reply.body,
                    json!({"ok": false, "error_code": 429_u16,
                        "description": "Too Many Requests: retry after 7",
                        "parameters": {"retry_after": 7_u64}})
                );
            }
            if *status == 302 {
                assert!(reply.head.contains(&format!("location: {target}")));
            }
        }
        assert_eq!(send(&fake, &token, &chat(5), "x").await?.status, 200);
        fake.shutdown().await?;
        Ok(())
    }

    /// A chat-scoped fault hits only the chat it names.
    // NOT cancel-safe: owns a fake Telegram task.
    #[tokio::test]
    async fn chat_scoped_fault_hits_only_that_chat() -> TestResult {
        let fake = FakeTelegram::spawn().await?;
        let token = token();
        fake.push_fault_for(7_i64, Fault::Forbidden);
        assert_eq!(send(&fake, &token, &chat(8), "x").await?.status, 200);
        assert_eq!(send(&fake, &token, &chat(7), "x").await?.status, 403);
        assert_eq!(send(&fake, &token, &chat(7), "x").await?.status, 200);
        fake.shutdown().await?;
        Ok(())
    }

    /// The 4096 limit counts UTF-16 code units: an astral character is two.
    // NOT cancel-safe: owns a fake Telegram task.
    #[tokio::test]
    async fn too_long_text_counts_utf16_code_units() -> TestResult {
        let fake = FakeTelegram::spawn().await?;
        let token = token();
        let astral = "\u{1F600}";
        let cases = [
            ("a".repeat(4096), 200),
            ("a".repeat(4097), 400),
            (astral.repeat(2048), 200),
            (astral.repeat(2049), 400),
        ];
        for (text, status) in cases {
            let reply = send(&fake, &token, &chat(1), &text).await?;
            assert_eq!(reply.status, status);
            if status == 400 {
                assert_eq!(
                    reply.body.get("description"),
                    Some(&json!("Bad Request: message is too long"))
                );
            }
        }
        fake.shutdown().await?;
        Ok(())
    }

    /// `wait_for_requests` resolves once enough requests arrived, with no polling.
    // NOT cancel-safe: owns a fake Telegram task.
    #[tokio::test]
    async fn wait_for_requests_resolves_when_requests_arrive() -> TestResult {
        let fake = FakeTelegram::spawn().await?;
        let token = token();
        let waiter = timeout(Duration::from_secs(10), fake.wait_for_requests(2));
        let sender = async {
            for _ in 0_u8..2_u8 {
                let _reply: Reply = send(&fake, &token, &chat(1), "x").await?;
            }
            TestResult::Ok(())
        };
        let (arrival, delivery) = tokio::join!(waiter, sender);
        arrival?;
        delivery?;
        timeout(Duration::from_secs(10), fake.wait_for_requests(1)).await?;
        fake.shutdown().await?;
        Ok(())
    }
}
