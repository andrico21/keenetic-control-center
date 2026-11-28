//! Router errors name their cause without carrying secrets or router values (todo 1).

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#![expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#![expect(
    clippy::tests_outside_test_module,
    reason = "this integration-test crate contains only tests"
)]

extern crate alloc;

use alloc::collections::BTreeMap;
use core::{error::Error, net::SocketAddr, str::FromStr as _, time::Duration};
use std::time::Instant;

use kcc_rci::{
    Admit, DecodeDetail, DecodeProblem, Deduper, JsonKind, RciError, RciPath, RouterUrl,
    TransportCause,
    auth::Credentials,
    decode_value,
    engine::{RciClient, RciClientOptions},
    not_json,
    observe::RequestOutcome,
    outbound::OutboundPolicy,
};
use kcc_testkit::{FakeRouter, FaultInjection, Handle, model::Profile};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// A router value planted in answers; no error text may carry it.
const PLANTED: &str = "SECRET-VALUE-7";

/// The login of the planted user.
const LOGIN: &str = "tester";

/// The planted user's password, built at run time.
fn password() -> String {
    format!("pw-{}-{}", PLANTED.len(), "x9q")
}

/// One row whose `static` field must be a boolean.
#[derive(Debug, Deserialize)]
struct Probe {
    #[serde(rename = "static")]
    _fixed: bool,
}

/// A fake router with the planted user and `faults`.
async fn serve(
    faults: FaultInjection,
) -> Result<(SocketAddr, Handle, String), Box<dyn Error + Send + Sync>> {
    let fake = FakeRouter::builder(Profile::default())
        .user(LOGIN, password(), ["cli", "http"])
        .faults(faults)
        .build()?;
    let cookie = fake.cookie_name().to_owned();
    let (address, handle) = fake.serve(([127, 0, 0, 1], 0).into()).await?;
    Ok((address, handle, cookie))
}

/// A client of `url` signing in as the planted user.
async fn client(url: &str, options: RciClientOptions) -> Result<RciClient, RciError> {
    let router = RouterUrl::from_str(url).map_err(|_error| RciError::Validation)?;
    let credentials = Credentials::new(LOGIN.to_owned(), SecretString::from(password()));
    RciClient::connect_with(
        router,
        credentials,
        options.with_outbound(OutboundPolicy::default().with_loopback(true)),
    )
    .await
}

/// The error of reading `show clock date` (with a planted query value) from `url`.
async fn read_error(url: &str) -> Result<RciError, Box<dyn Error + Send + Sync>> {
    let client = match client(url, RciClientOptions::default()).await {
        Ok(client) => client,
        Err(error) => return Ok(error),
    };
    let path = RciPath::from_segments(["show", "clock", "date"])?;
    match client.get(&path, &[("name", PLANTED)]).await {
        Ok(body) => Err(format!("read succeeded: {body:?}").into()),
        Err(error) => Ok(error),
    }
}

/// Asserts that neither text of `error` carries a planted value, the password, the
/// cookie, the query or the router's port.
fn assert_clean(error: &RciError, port: u16, cookie: &str) {
    for text in [error.to_string(), format!("{error:?}")] {
        for forbidden in [
            PLANTED,
            password().as_str(),
            cookie,
            "name=",
            port.to_string().as_str(),
        ] {
            assert!(
                !text.contains(forbidden),
                "{text:?} carries a forbidden value"
            );
        }
    }
}

/// (a) A port nobody listens on is a refused connection.
#[tokio::test]
async fn a_closed_port_is_connection_refused() -> TestResult {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let address = listener.local_addr()?;
    drop(listener);

    let error = read_error(&format!("http://{address}")).await?;

    assert!(
        matches!(error, RciError::Transport(TransportCause::ConnectRefused)),
        "{error:?}"
    );
    assert!(error.to_string().contains("connection refused"), "{error}");
    assert_eq!(format!("{error:?}"), "Transport(ConnectRefused)");
    assert_eq!(
        RequestOutcome::of(&Err::<(), _>(error)).as_str(),
        "transport_error"
    );
    Ok(())
}

/// (b) A connection closed after the request, before any status line.
#[tokio::test]
async fn a_connection_closed_before_the_answer_is_named() -> TestResult {
    let (address, handle, cookie) =
        serve(FaultInjection::default().close_before_answer("show/clock")).await?;

    let error = read_error(&format!("http://{address}")).await?;

    assert!(
        matches!(
            error,
            RciError::Transport(TransportCause::ClosedBeforeAnswer)
        ),
        "{error:?}"
    );
    assert_clean(&error, address.port(), &cookie);
    handle.shutdown().await?;
    Ok(())
}

/// (c) An answer shorter than its announced length is cut off.
#[tokio::test]
async fn a_cut_body_is_named() -> TestResult {
    let (address, handle, cookie) = serve(FaultInjection::default().cut_body("show/clock")).await?;

    let error = read_error(&format!("http://{address}")).await?;

    assert!(
        matches!(error, RciError::Transport(TransportCause::BodyInterrupted)),
        "{error:?}"
    );
    assert!(
        error.to_string().contains("the answer was cut off"),
        "{error}"
    );
    assert_clean(&error, address.port(), &cookie);
    handle.shutdown().await?;
    Ok(())
}

/// (d) TLS to a plain-HTTP port fails in the TLS layer.
#[tokio::test]
async fn tls_to_a_plain_port_is_a_tls_failure() -> TestResult {
    let (address, handle, cookie) = serve(FaultInjection::default()).await?;

    let error = read_error(&format!("https://{address}")).await?;

    assert!(
        matches!(error, RciError::Transport(TransportCause::Tls(_))),
        "{error:?}"
    );
    assert_clean(&error, address.port(), &cookie);
    handle.shutdown().await?;
    Ok(())
}

/// (e) An HTTP error names its status in both texts.
#[tokio::test]
async fn an_http_error_names_its_status() -> TestResult {
    let (address, handle, cookie) =
        serve(FaultInjection::default().fail_read_matching("show/clock", 1)).await?;

    let error = read_error(&format!("http://{address}")).await?;

    assert!(error.to_string().contains("500"), "{error}");
    assert_eq!(format!("{error:?}"), "Http { status: 500 }");
    assert_clean(&error, address.port(), &cookie);
    assert_eq!(
        RequestOutcome::of(&Err::<(), _>(error)).as_str(),
        "http_error"
    );
    handle.shutdown().await?;
    Ok(())
}

/// (f) A decode failure names the path, the JSON kind found and what was expected.
#[test]
fn a_decode_failure_names_path_and_kinds() -> TestResult {
    let whole = decode_value::<Vec<u8>>("show x", &json!({"host":[{"rssi":PLANTED}]}))
        .err()
        .ok_or("an object decoded as a list")?;
    assert_eq!(whole.path, "$");
    assert!(
        matches!(
            &whole.problem,
            DecodeProblem::Mismatch {
                found: JsonKind::Object,
                expected: _
            }
        ),
        "{whole:?}"
    );

    let row = decode_value::<Vec<Probe>>("show x", &json!([{"static": PLANTED}]))
        .err()
        .ok_or("a string decoded as a boolean")?;
    assert_eq!(row.path, "$[0].static");
    assert_eq!(
        row.problem,
        DecodeProblem::Mismatch {
            found: JsonKind::String,
            expected: "a boolean".to_owned(),
        }
    );
    let error = RciError::Decode(row);
    assert_eq!(
        error.to_string(),
        "the router's answer could not be read: show x at $[0].static: found string, expected a boolean"
    );
    assert_eq!(RequestOutcome::of(&Err::<(), _>(error)).as_str(), "error");
    Ok(())
}

/// (g) A map key that is not a plain name is masked in the path.
#[test]
fn a_value_like_map_key_is_masked() -> TestResult {
    let keyed = decode_value::<BTreeMap<String, Probe>>(
        "show x",
        &json!({"02:00:00:00:00:01": {"static": PLANTED}}),
    )
    .err()
    .ok_or("a string decoded as a boolean")?;
    assert_eq!(keyed.path, "$.*.static");
    assert!(
        matches!(
            &keyed.problem,
            DecodeProblem::Mismatch {
                found: JsonKind::String,
                expected: _
            }
        ),
        "{keyed:?}"
    );
    let missing = decode_value::<Vec<Probe>>("show x", &json!([{}]))
        .err()
        .ok_or("a missing field decoded")?;
    assert_eq!(
        missing.problem,
        DecodeProblem::Missing {
            field: "static".to_owned()
        }
    );
    Ok(())
}

/// (h) Neither text of a decode error or a non-JSON answer carries a router value.
#[test]
fn decode_texts_carry_no_router_value() -> TestResult {
    let errors = [
        decode_value::<Vec<Probe>>("show x", &json!([{"static": PLANTED}])).err(),
        decode_value::<Vec<u8>>("show x", &json!({ PLANTED: 1_i32 })).err(),
        decode_value::<BTreeMap<String, Probe>>("show x", &json!({"02:00:00:00:00:01": PLANTED}))
            .err(),
        Some(not_json(
            "show x",
            format!("<html>{PLANTED}</html>").as_bytes(),
        )),
    ];
    for found in errors {
        let error = RciError::Decode(found.ok_or("a wrong answer decoded")?);
        for text in [error.to_string(), format!("{error:?}")] {
            assert!(!text.contains(PLANTED), "{text:?}");
        }
    }
    let html: Box<DecodeDetail> = not_json("show x", b"  <html></html>");
    assert_eq!(html.to_string(), "show x: not JSON (15 bytes, HTML)");
    Ok(())
}

/// Router text containing `expected ` never reaches the `expected` text (todo 1).
#[test]
fn router_text_with_the_word_expected_stays_out() -> TestResult {
    let planted = format!("a expected {PLANTED}");
    let found = decode_value::<Vec<Probe>>("show x", &json!([{"static": planted}]))
        .err()
        .ok_or("a wrong answer decoded")?;
    let DecodeProblem::Mismatch { expected, found: _ } = &found.problem else {
        return Err(format!("not a mismatch: {:?}", found.problem).into());
    };
    assert_eq!(expected, "a boolean");
    let error = RciError::Decode(found);
    for text in [error.to_string(), format!("{error:?}")] {
        assert!(!text.contains(PLANTED), "{text:?}");
    }
    Ok(())
}

/// A decoder's `expected one of` list is cut at 80 characters (todo 1).
#[test]
fn a_long_expected_list_is_cut() -> TestResult {
    #[derive(Debug, Deserialize)]
    enum Long {
        AlphaMode,
        BetaStrategy,
        GammaSetting,
        DeltaPolicy,
        EpsilonProfile,
    }
    let found = decode_value::<Long>("show x", &json!("zz"))
        .err()
        .ok_or("a wrong answer decoded")?;
    let DecodeProblem::Mismatch { expected, found: _ } = &found.problem else {
        return Err(format!("not a mismatch: {:?}", found.problem).into());
    };
    assert_eq!(expected.chars().count(), 80, "{expected:?}");
    Ok(())
}

/// (j) A background start answered without a process id names the missing pointer.
///
/// The answer must be no JSON object either: a JSON object without a process id is the
/// first chunk of a router that continues in the session (todo 28). A one-shot `show log`
/// of a router with no records answers text.
#[tokio::test]
async fn a_background_answer_without_a_process_id_names_the_pointer() -> TestResult {
    let (address, handle, cookie) = serve(FaultInjection::default()).await?;
    let client = client(&format!("http://{address}"), RciClientOptions::default()).await?;
    let path = RciPath::from_segments(["show", "log"])?;

    let started = client.start(path, &json!({})).await;

    let error = started
        .err()
        .ok_or("a start without a process id succeeded")?;
    let RciError::Decode(detail) = &error else {
        return Err(format!("not a decode error: {error:?}").into());
    };
    assert_eq!(
        detail.problem,
        DecodeProblem::MissingPointer {
            pointer: "/process/id".to_owned()
        }
    );
    assert_clean(&error, address.port(), &cookie);
    handle.shutdown().await?;
    Ok(())
}

/// (k) Identical lines within the window collapse; the next one counts them.
#[test]
fn the_deduper_collapses_a_burst_and_counts_it() -> TestResult {
    let start = Instant::now();
    let key = || {
        (
            "lab-1".to_owned(),
            "GET".to_owned(),
            "show/x".to_owned(),
            "dns".to_owned(),
        )
    };
    let mut deduper = Deduper::default();
    let mut admits = Vec::new();
    for second in 0..20_u64 {
        let now = start
            .checked_add(Duration::from_secs(second))
            .ok_or("instant")?;
        admits.push(deduper.admit(key(), now));
    }
    assert_eq!(admits.first(), Some(&Admit::Log { suppressed: 0 }));
    assert_eq!(
        admits
            .iter()
            .filter(|admit| **admit == Admit::Suppress)
            .count(),
        19
    );
    let later = start
        .checked_add(Duration::from_secs(61))
        .ok_or("instant")?;
    assert_eq!(deduper.admit(key(), later), Admit::Log { suppressed: 19 });
    Ok(())
}

/// (k) The 257th key evicts the oldest one.
#[test]
fn the_deduper_evicts_its_oldest_key() -> TestResult {
    let start = Instant::now();
    let key = |index: u32| {
        (
            "lab-1".to_owned(),
            "GET".to_owned(),
            format!("p{index}"),
            "dns".to_owned(),
        )
    };
    let mut deduper = Deduper::default();
    for index in 0..257_u32 {
        let now = start
            .checked_add(Duration::from_millis(u64::from(index)))
            .ok_or("instant")?;
        assert_eq!(deduper.admit(key(index), now), Admit::Log { suppressed: 0 });
    }
    let now = start.checked_add(Duration::from_secs(1)).ok_or("instant")?;
    assert_eq!(deduper.admit(key(1), now), Admit::Suppress, "kept");
    assert_eq!(
        deduper.admit(key(0), now),
        Admit::Log { suppressed: 0 },
        "evicted"
    );
    Ok(())
}

/// (l) The client keeps the router id it was given for its log lines.
#[tokio::test]
async fn the_client_keeps_its_log_id() -> TestResult {
    let (address, handle, _cookie) = serve(FaultInjection::default()).await?;
    let url = format!("http://{address}");

    let named = client(
        &url,
        RciClientOptions::default().with_log_id("lab-1".to_owned()),
    )
    .await?;
    let unnamed = client(&url, RciClientOptions::default()).await?;

    assert_eq!(named.log_id(), "lab-1");
    assert_eq!(unnamed.log_id(), "");
    handle.shutdown().await?;
    Ok(())
}
