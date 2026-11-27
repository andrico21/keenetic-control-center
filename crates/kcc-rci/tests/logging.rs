//! Every router request is logged at debug and each failure once at warn, without a
//! secret, query or router value in any line (todo 2).

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

#[path = "support/planted_router.rs"]
mod planted_router;

extern crate alloc;

use alloc::sync::Arc;
use core::{error::Error, net::SocketAddr, str::FromStr as _};
use std::{
    io,
    sync::{Mutex, PoisonError},
};

use kcc_rci::{
    RciError, RciPath, RouterUrl,
    auth::Credentials,
    auth_options::{Mode, Options},
    engine::{RciClient, RciClientOptions},
    outbound::OutboundPolicy,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle,
    auth_fixture::{self, Options as Fixture, Protocol},
    leak::contains_secret,
    model::Profile,
    outbound::connect_manager_with_options,
};
use secrecy::SecretString;
use tokio::net::TcpListener;
use tracing::{
    Level,
    subscriber::{DefaultGuard, set_default},
};
use tracing_subscriber::fmt::MakeWriter;

use self::planted_router::{Planted, PlantedRouter};

type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

/// The router profile id every client of these tests carries.
const LOG_ID: &str = "router-7";

/// Everything the subscriber writes.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    /// Starts capturing every event of this thread at TRACE.
    fn start() -> (Self, DefaultGuard) {
        let captured = Self::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(Level::TRACE)
            .with_writer(captured.clone())
            .finish();
        let guard = set_default(subscriber);
        (captured, guard)
    }

    /// The text written so far.
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }

    /// The lines written so far at `level` (`DEBUG`, `WARN`, ...).
    fn lines_at(&self, level: &str) -> Vec<String> {
        let marker = format!(" {level} ");
        self.text()
            .lines()
            .filter(|line| line.contains(&marker))
            .map(str::to_owned)
            .collect()
    }
}

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Captured {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// A fake router with `faults`.
async fn serve(
    faults: FaultInjection,
) -> Result<(SocketAddr, Handle), Box<dyn Error + Send + Sync>> {
    let fake = FakeRouter::builder(Profile::default())
        .faults(faults)
        .build()?;
    Ok(fake.serve(([127, 0, 0, 1], 0).into()).await?)
}

/// A client of `url` that logs as [`LOG_ID`] and signs in with `password`.
async fn client(url: &str, password: &str) -> Result<RciClient, RciError> {
    let router = RouterUrl::from_str(url).map_err(|_error| RciError::Validation)?;
    let credentials = Credentials::new(DEFAULT_LOGIN.to_owned(), SecretString::from(password));
    RciClient::connect_with(
        router,
        credentials,
        RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true))
            .with_log_id(LOG_ID.to_owned()),
    )
    .await
}

/// A read of `show/version` logs one DEBUG answer line with the router id, and no warning.
#[tokio::test]
async fn a_successful_read_logs_one_debug_answer_line() -> TestResult {
    let (address, handle) = serve(FaultInjection::default()).await?;
    let (captured, _guard) = Captured::start();
    let client = client(&format!("http://{address}"), DEFAULT_PASSWORD).await?;

    drop(
        client
            .get(&RciPath::from_segments(["show", "version"])?, &())
            .await?,
    );

    let answers = captured
        .lines_at("DEBUG")
        .into_iter()
        .filter(|line| line.contains("method=GET path=/rci/show/version status=200"))
        .collect::<Vec<_>>();
    assert_eq!(answers.len(), 1, "{}", captured.text());
    assert!(
        answers
            .iter()
            .all(|line| line.contains(&format!("router={LOG_ID}")) && line.contains(" ms=")),
        "{answers:?}"
    );
    assert!(
        captured
            .lines_at("DEBUG")
            .iter()
            .any(|line| line.contains("signed in") && line.contains(&format!("router={LOG_ID}"))),
        "{}",
        captured.text()
    );
    assert!(captured.lines_at("WARN").is_empty(), "{}", captured.text());
    handle.shutdown().await?;
    Ok(())
}

/// A port nobody listens on logs exactly one warning naming the refused connection.
#[tokio::test]
async fn a_refused_connection_logs_one_warning() -> TestResult {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let address = listener.local_addr()?;
    drop(listener);
    let (captured, _guard) = Captured::start();
    let client = client(&format!("http://{address}"), DEFAULT_PASSWORD).await?;

    let result = client
        .get(&RciPath::from_segments(["show", "version"])?, &())
        .await;

    assert!(result.is_err(), "{result:?}");
    let warnings = captured.lines_at("WARN");
    assert_eq!(warnings.len(), 1, "{}", captured.text());
    assert!(
        warnings
            .iter()
            .all(|line| line.contains("cause=connect_refused")
                && line.contains(&format!("router={LOG_ID}"))
                && line.contains("path=/rci/show/version")
                && line.contains(" ms=")
                && !line.contains(&format!(":{}", address.port()))),
        "{warnings:?}"
    );
    Ok(())
}

/// A missing resource is expected on routers without a feature: debug only, no warning.
#[tokio::test]
async fn a_missing_resource_logs_no_warning() -> TestResult {
    let (address, handle) = serve(FaultInjection::default()).await?;
    let (captured, _guard) = Captured::start();
    let client = client(&format!("http://{address}"), DEFAULT_PASSWORD).await?;

    let result = client
        .get(&RciPath::from_segments(["show", "kcc-absent"])?, &())
        .await;

    assert!(matches!(result, Err(RciError::NotFound)), "{result:?}");
    assert!(captured.lines_at("WARN").is_empty(), "{}", captured.text());
    assert!(
        captured
            .lines_at("DEBUG")
            .iter()
            .any(|line| line.contains("path=/rci/show/kcc-absent status=404")),
        "{}",
        captured.text()
    );
    assert!(
        captured
            .lines_at("DEBUG")
            .iter()
            .any(|line| line.contains("path=/rci/show/kcc-absent")
                && line.contains("cause=not_found")),
        "{}",
        captured.text()
    );
    handle.shutdown().await?;
    Ok(())
}

/// A query is dropped from the logged path and only its presence is noted.
#[tokio::test]
async fn a_query_is_noted_but_never_logged() -> TestResult {
    let (address, handle) = serve(FaultInjection::default()).await?;
    let (captured, _guard) = Captured::start();
    let client = client(&format!("http://{address}"), DEFAULT_PASSWORD).await?;
    let planted = ["PLANTED", "NAME"].join("-");

    drop(
        client
            .get(
                &RciPath::from_segments(["show", "clock", "date"])?,
                &[("name", planted.as_str())],
            )
            .await,
    );

    let text = captured.text();
    assert!(
        text.lines()
            .any(|line| line.contains("path=/rci/show/clock/date query=true")),
        "{text}"
    );
    assert!(!contains_secret(&text, &planted), "{text}");
    assert!(!text.contains("name="), "{text}");
    handle.shutdown().await?;
    Ok(())
}

/// Answers carrying a password, a MAC address and a client name, a 500 carrying them, and
/// a router error naming a client leave none of them, nor the router password or the
/// session cookie, in any line.
#[tokio::test]
async fn planted_secrets_and_router_values_never_reach_a_line() -> TestResult {
    let planted = Planted::new();
    let router = PlantedRouter::spawn(planted.clone()).await?;
    let password = format!("router-pw-{}", 31_u8);
    let (captured, _guard) = Captured::start();
    let client = client(&router.url(), &password).await?;

    drop(
        client
            .get(&RciPath::from_segments(["show", "planted"])?, &())
            .await?,
    );
    let broken = client
        .get(&RciPath::from_segments(["show", "broken"])?, &())
        .await;
    let refusing = client
        .get(&RciPath::from_segments(["show", "refusing"])?, &())
        .await;
    client.logout().await;

    assert!(
        matches!(broken, Err(RciError::Http { status: 500 })),
        "{broken:?}"
    );
    assert!(
        matches!(
            refusing,
            Err(RciError::Rci {
                pointer: _,
                code: _,
                ident: _,
                message: _
            })
        ),
        "{refusing:?}"
    );
    let text = captured.text();
    for forbidden in planted.all().into_iter().chain([password.as_str()]) {
        assert!(
            !contains_secret(&text, forbidden),
            "a planted value leaked: {text}"
        );
    }
    let warnings = captured.lines_at("WARN");
    assert!(
        warnings
            .iter()
            .any(|line| line.contains("path=/rci/show/broken") && line.contains("cause=http_500")),
        "{text}"
    );
    assert!(
        warnings
            .iter()
            .any(|line| line.contains("path=/rci/show/refusing")
                && line.contains("cause=router_error")
                && line.contains("Command::Base")
                && line.contains("7405600")),
        "{text}"
    );
    Ok(())
}

/// Two pages reading the same failing resource through one shared client leave one
/// warning; a different failure still gets its own.
#[tokio::test]
async fn two_pages_sharing_one_client_warn_once() -> TestResult {
    let (address, handle) = serve(
        FaultInjection::default()
            .fail_read_matching("show/system", 2)
            .fail_read_matching("show/clock", 1),
    )
    .await?;
    let (captured, _guard) = Captured::start();
    let shared = Arc::new(client(&format!("http://{address}"), DEFAULT_PASSWORD).await?);
    let system = RciPath::from_segments(["show", "system"])?;
    let (dashboard, status) = (Arc::clone(&shared), Arc::clone(&shared));

    let first = dashboard.get(&system, &()).await;
    let second = status.show(&system, &()).await;
    let other = shared
        .get(&RciPath::from_segments(["show", "clock", "date"])?, &())
        .await;

    assert!(
        first.is_err() && second.is_err() && other.is_err(),
        "{first:?} {second:?} {other:?}"
    );
    let warnings = captured.lines_at("WARN");
    assert_eq!(
        warnings
            .iter()
            .filter(|line| line.contains("path=/rci/show/system"))
            .count(),
        1,
        "{}",
        captured.text()
    );
    assert_eq!(
        warnings
            .iter()
            .filter(|line| line.contains("path=/rci/show/clock/date"))
            .count(),
        1,
        "{}",
        captured.text()
    );
    handle.shutdown().await?;
    Ok(())
}

/// A refused sign-in logs one warning naming the refusal, never the login or password.
#[tokio::test]
async fn a_refused_sign_in_warns_with_its_variant_name() -> TestResult {
    let (address, handle) = serve(FaultInjection::default()).await?;
    let (captured, _guard) = Captured::start();
    let wrong = format!("wrong-pw-{}", 59_u8);
    let client = client(&format!("http://{address}"), &wrong).await?;

    let result = client
        .get(&RciPath::from_segments(["show", "version"])?, &())
        .await;

    assert!(matches!(result, Err(RciError::Auth(_))), "{result:?}");
    let text = captured.text();
    let sign_in = captured
        .lines_at("WARN")
        .into_iter()
        .filter(|line| line.contains("sign-in failed"))
        .collect::<Vec<_>>();
    assert_eq!(sign_in.len(), 1, "{text}");
    assert!(
        sign_in
            .iter()
            .all(|line| line.contains("error=Rejected")
                && line.contains(&format!("router={LOG_ID}"))),
        "{text}"
    );
    assert!(!contains_secret(&text, &wrong), "{text}");
    assert!(!text.contains(&format!("login={DEFAULT_LOGIN}")), "{text}");
    handle.shutdown().await?;
    Ok(())
}

/// The same failing path with a different cause is a different failure: it warns again
/// (todo 2).
#[tokio::test]
async fn the_same_path_with_another_cause_warns_again() -> TestResult {
    let planted = Planted::new();
    let router = PlantedRouter::spawn(planted).await?;
    let (captured, _guard) = Captured::start();
    let client = client(&router.url(), "router-pw-31").await?;
    let path = RciPath::from_segments(["show", "flapping"])?;

    let first = client.get(&path, &()).await;
    let second = client.get(&path, &()).await;
    let third = client.get(&path, &()).await;

    assert!(
        matches!(first, Err(RciError::Http { status: 500 })),
        "{first:?}"
    );
    assert!(
        matches!(second, Err(RciError::Http { status: 503 })),
        "{second:?}"
    );
    assert!(
        matches!(third, Err(RciError::Http { status: 503 })),
        "{third:?}"
    );
    let warnings = captured
        .lines_at("WARN")
        .into_iter()
        .filter(|line| line.contains("path=/rci/show/flapping"))
        .collect::<Vec<_>>();
    assert_eq!(warnings.len(), 2, "{}", captured.text());
    assert_eq!(
        warnings
            .iter()
            .filter(|line| line.contains("cause=http_500"))
            .count(),
        1,
        "{warnings:?}"
    );
    assert_eq!(
        warnings
            .iter()
            .filter(|line| line.contains("cause=http_503"))
            .count(),
        1,
        "{warnings:?}"
    );
    Ok(())
}

/// A detection that cannot decode `show version` warns once, with the decode cause on
/// that path (todo 2).
#[tokio::test]
async fn a_failed_detection_warns_once_with_the_decode_cause() -> TestResult {
    let mut planted = Planted::new();
    planted.version = serde_json::json!({"release": {"major": "five"}});
    let router = PlantedRouter::spawn(planted).await?;
    let (captured, _guard) = Captured::start();
    let client = client(&router.url(), "router-pw-31").await?;

    let result = client.detect().await;

    assert!(matches!(result, Err(RciError::Decode(_))), "{result:?}");
    let warnings = captured.lines_at("WARN");
    assert_eq!(warnings.len(), 1, "{}", captured.text());
    assert!(
        warnings.iter().all(|line| line.contains("cause=decode")
            && line.contains("path=/rci/show/version")
            && line.contains(&format!("router={LOG_ID}"))),
        "{warnings:?}"
    );
    Ok(())
}

/// Optional resources a router lacks are answered `None` and logged at DEBUG only
/// (todo 2).
#[tokio::test]
async fn an_absent_optional_resource_logs_at_debug_only() -> TestResult {
    let router = PlantedRouter::spawn(Planted::new()).await?;
    let (captured, _guard) = Captured::start();
    let client = client(&router.url(), "router-pw-31").await?;

    let info = client.detect().await;

    assert!(info.is_ok(), "{info:?}");
    assert!(captured.lines_at("WARN").is_empty(), "{}", captured.text());
    let absent = captured
        .lines_at("DEBUG")
        .into_iter()
        .filter(|line| line.contains("cause=http_404"))
        .collect::<Vec<_>>();
    assert_eq!(
        absent
            .iter()
            .filter(|line| line.contains("path=/rci/show/identification"))
            .count(),
        1,
        "{}",
        captured.text()
    );
    assert!(
        absent
            .iter()
            .all(|line| line.contains(&format!("router={LOG_ID}"))),
        "{absent:?}"
    );
    Ok(())
}

/// A body read logs one DEBUG line with the path and the byte count (todo 2).
#[tokio::test]
async fn a_body_read_logs_its_byte_count() -> TestResult {
    let (address, handle) = serve(FaultInjection::default()).await?;
    let (captured, _guard) = Captured::start();
    let client = client(&format!("http://{address}"), DEFAULT_PASSWORD).await?;

    let body = client
        .get(&RciPath::from_segments(["show", "version"])?, &())
        .await?;

    let reads = captured
        .lines_at("DEBUG")
        .into_iter()
        .filter(|line| line.contains("path=/rci/show/version bytes="))
        .collect::<Vec<_>>();
    assert_eq!(reads.len(), 1, "{}", captured.text());
    let counted = reads
        .iter()
        .filter_map(|line| line.split("bytes=").nth(1))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|digits| digits.parse::<usize>().ok())
        .collect::<Vec<_>>();
    assert_eq!(counted.len(), 1, "{reads:?}");
    assert!(
        counted.iter().all(|bytes| *bytes > 0),
        "{counted:?} {body:?}"
    );
    handle.shutdown().await?;
    Ok(())
}

/// A digest sign-in and the requests it signs are logged like any other: the unsigned
/// request, its 401 and the signed replay each leave an answer line (todo 2).
#[tokio::test]
async fn digest_requests_log_their_answers() -> TestResult {
    let mut fixture = Fixture::default();
    fixture.protocol = Protocol::DigestSha256;
    let (address, handle, _counts) = auth_fixture::spawn(fixture).await?;
    let (captured, _guard) = Captured::start();
    let mut options = Options::default();
    options.mode = Mode::DigestProxy;
    let credentials = Credentials::new("admin".to_owned(), SecretString::from("admin"));
    let manager = connect_manager_with_options(
        (
            RouterUrl::from_str(&format!("http://{address}"))?,
            &OutboundPolicy::default().with_loopback(true),
        ),
        Some(credentials),
        options,
    )
    .await?
    .with_log_id(LOG_ID.to_owned());

    let first = manager.get("/rci/show/clock").await?;
    let second = manager.get("/rci/show/clock").await?;

    assert!(first.status().is_success() && second.status().is_success());
    let answers = captured
        .lines_at("DEBUG")
        .into_iter()
        .filter(|line| {
            line.contains(&format!(
                "router={LOG_ID} method=GET path=/rci/show/clock status="
            ))
        })
        .collect::<Vec<_>>();
    let count = |status: &str| {
        answers
            .iter()
            .filter(|line| line.contains(&format!("status={status} ")))
            .count()
    };
    assert_eq!(count("401"), 1, "{}", captured.text());
    assert_eq!(count("200"), 2, "{}", captured.text());
    handle.shutdown().await?;
    Ok(())
}
