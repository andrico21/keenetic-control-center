//! A router answer kcc cannot read names its command, field path and JSON kinds, logs one
//! warning with the router id, and never carries an answer value (todo 3).

#![expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    clippy::tests_outside_test_module,
    reason = "integration tests use assertions and a boxed error result"
)]

extern crate alloc;

mod support;

use alloc::sync::Arc;
use core::str::FromStr as _;

use kcc_catalog::Catalog;
use kcc_domain::{DomainError, RouterCtx, dhcp, interfaces, nat, router_users, routing::read};
use kcc_rci::{
    DecodeDetail, DecodeProblem, JsonKind, ObjectName, RciClient, RciClientOptions, RouterUrl,
    auth::Credentials, outbound::OutboundPolicy,
};
use kcc_testkit::{
    DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter, FaultInjection, Handle,
    model::{Firmware, Model, Profile},
};
use secrecy::SecretString;
use serde_json::{Value, json};

use crate::support::{PROFILES, TestResult, TraceCapture};

/// A planted answer value that must never reach an error text or a log line; built at run
/// time so no source literal carries it.
fn planted() -> String {
    ["SECRET", "VALUE", "9"].join("-")
}

/// Serves a KN-1811 on `firmware` with `fixtures` and `faults`; the client logs as
/// `log_id`.
async fn router(
    firmware: Firmware,
    fixtures: &[(&str, Value)],
    faults: FaultInjection,
    log_id: &str,
) -> TestResult<(RouterCtx, Handle)> {
    let builder = fixtures.iter().fold(
        FakeRouter::builder(Profile::new(Model::Kn1811, firmware)?).faults(faults),
        |builder, (path, value)| builder.show_fixture(*path, value.clone()),
    );
    let (address, handle) = builder
        .reached_directly()
        .build()?
        .serve(([127, 0, 0, 1], 0).into())
        .await?;
    let client = RciClient::connect_with(
        RouterUrl::from_str(&format!("http://{address}"))?,
        Credentials::new(
            DEFAULT_LOGIN.to_owned(),
            SecretString::from(DEFAULT_PASSWORD.to_owned()),
        ),
        RciClientOptions::default()
            .with_outbound(OutboundPolicy::default().with_loopback(true))
            .with_log_id(log_id.to_owned()),
    )
    .await?;
    let catalog = Catalog::for_router(&client.detect().await?)?;
    Ok((RouterCtx::new(Arc::new(client), catalog), handle))
}

/// The detail of an `UnreadableAnswer`, or a test failure naming what came instead.
fn unreadable<T>(outcome: kcc_domain::Result<T>) -> TestResult<(String, Box<DecodeDetail>)> {
    match outcome {
        Err(error @ DomainError::UnreadableAnswer(_)) => {
            let text = error.to_string();
            let DomainError::UnreadableAnswer(detail) = error else {
                return Err("matched above".into());
            };
            Ok((text, detail))
        }
        Err(other) => Err(format!("expected UnreadableAnswer, got {other:?}").into()),
        Ok(_) => Err("expected UnreadableAnswer, got rows".into()),
    }
}

/// A route row whose `static` is a string names `$[0].static` and the kinds, and keeps
/// the value out of the error and the log.
///
/// The same failure of the same router on the next profile logs no second warning.
#[tokio::test]
async fn a_mistyped_field_names_its_path_and_kinds_but_not_its_value() -> TestResult {
    let trace = TraceCapture::install();
    let planted = planted();
    for firmware in PROFILES {
        let (context, handle) = router(
            firmware,
            &[("ip/route", json!([{ "static": planted }]))],
            FaultInjection::default(),
            "r1",
        )
        .await?;

        let (text, detail) = unreadable(read::ipv4_table(&context).await)?;

        assert_eq!(detail.resource, "show ip route");
        assert_eq!(detail.path, "$[0].static");
        let DecodeProblem::Mismatch { found, expected } = &detail.problem else {
            return Err(format!("expected a mismatch, got {:?}", detail.problem).into());
        };
        assert_eq!((*found, expected.as_str()), (JsonKind::String, "a boolean"));
        assert!(
            text.starts_with("the router's answer could not be read: show ip route at $[0].static"),
            "{text}"
        );
        assert!(!text.contains(&planted), "{text}");
        assert!(!format!("{detail:?}").contains(&planted));
        handle.shutdown().await?;
    }
    let log = trace.text()?;
    let warnings: Vec<&str> = log
        .lines()
        .filter(|line| line.contains(" WARN ") && line.contains("kcc_domain::decode"))
        .collect();
    let [warning] = warnings.as_slice() else {
        return Err(format!("expected one decode warning in {log}").into());
    };
    for field in [
        "router=r1",
        "resource=show ip route",
        "path=$[0].static",
        "problem=mismatch",
    ] {
        assert!(warning.contains(field), "{field} missing in {warning}");
    }
    assert!(!log.contains(&planted), "{log}");
    Ok(())
}

/// An object where the decoder wants a list fails at `$` with found `Object`. The fake
/// rewrites `show ipv6 route` into a list, so the bare-array `show ip arp` read carries the
/// envelope case.
#[tokio::test]
async fn an_object_where_a_list_is_expected_fails_at_the_root() -> TestResult {
    let _trace = TraceCapture::install();
    for firmware in PROFILES {
        let (context, handle) = router(
            firmware,
            &[("ip/arp", json!({ "arp": [] }))],
            FaultInjection::default(),
            "r3",
        )
        .await?;

        let (_text, detail) = unreadable(dhcp::read_neighbours(&context).await)?;

        assert_eq!(
            (detail.resource.as_str(), detail.path.as_str()),
            ("show ip arp", "$")
        );
        assert!(
            matches!(
                detail.problem,
                DecodeProblem::Mismatch {
                    found: JsonKind::Object,
                    expected: _
                }
            ),
            "{:?}",
            detail.problem
        );
        handle.shutdown().await?;
    }
    Ok(())
}

/// A text answer where JSON is expected is `NotJson` with its length only.
#[tokio::test]
async fn a_text_answer_is_not_json() -> TestResult {
    let trace = TraceCapture::install();
    let planted = planted();
    let body = format!("plain text {planted}");
    for firmware in PROFILES {
        let (context, handle) = router(
            firmware,
            &[],
            FaultInjection::default().show_answers_text("show/ip/route", body.clone()),
            "r4",
        )
        .await?;

        let (text, detail) = unreadable(read::ipv4_table(&context).await)?;

        assert_eq!(detail.resource, "show ip route");
        assert_eq!(
            detail.problem,
            DecodeProblem::NotJson {
                bytes: body.len(),
                html: false
            }
        );
        assert!(!text.contains(&planted), "{text}");
        handle.shutdown().await?;
    }
    assert!(!trace.text()?.contains(&planted));
    Ok(())
}

/// The decode warnings of `log`, one per line.
fn decode_warnings(log: &str) -> Vec<&str> {
    log.lines()
        .filter(|line| line.contains(" WARN ") && line.contains("kcc_domain::decode"))
        .collect()
}

/// The same router and resource failing in two ways logs one warning per problem kind: the
/// dedupe key carries the kind.
#[tokio::test]
async fn one_resource_failing_in_two_ways_warns_once_per_kind() -> TestResult {
    let trace = TraceCapture::install();
    let firmware = PROFILES[0];
    let (mistyped, first) = router(
        firmware,
        &[("ip/route", json!([{ "static": "x" }]))],
        FaultInjection::default(),
        "r5",
    )
    .await?;
    drop(unreadable(read::ipv4_table(&mistyped).await)?);
    let (text, second) = router(
        firmware,
        &[],
        FaultInjection::default().show_answers_text("show/ip/route", "plain text"),
        "r5",
    )
    .await?;
    drop(unreadable(read::ipv4_table(&text).await)?);
    first.shutdown().await?;
    second.shutdown().await?;

    let log = trace.text()?;
    let warnings = decode_warnings(&log);
    let [mismatch, not_json] = warnings.as_slice() else {
        return Err(format!("expected two decode warnings in {log}").into());
    };
    assert!(mismatch.contains("problem=mismatch"), "{mismatch}");
    assert!(not_json.contains("problem=not_json"), "{not_json}");
    Ok(())
}

/// NAT sessions answered with text are `UnreadableAnswer` naming `show ip nat`.
#[tokio::test]
async fn nat_sessions_answered_with_text_are_unreadable() -> TestResult {
    let _trace = TraceCapture::install();
    let (context, handle) = router(
        PROFILES[0],
        &[],
        FaultInjection::default().show_answers_text("show/ip/nat", "plain text"),
        "r6",
    )
    .await?;

    let (_text, detail) = unreadable(nat::read::sessions_page(&context, 0).await)?;

    assert_eq!(detail.resource, "show ip nat");
    assert!(matches!(
        detail.problem,
        DecodeProblem::NotJson { bytes: _, html: _ }
    ));
    handle.shutdown().await?;
    Ok(())
}

/// A mistyped interface field is `UnreadableAnswer` naming `show interface`.
#[tokio::test]
async fn a_mistyped_interface_is_unreadable() -> TestResult {
    let _trace = TraceCapture::install();
    let (context, handle) = router(
        PROFILES[0],
        &[("interface", json!({ "Bridge0": { "priority": "high" } }))],
        FaultInjection::default(),
        "r7",
    )
    .await?;

    let name = ObjectName::try_from("Bridge0".to_owned())?;
    let (_text, detail) = unreadable(interfaces::read_interface(&context, &name).await)?;

    assert_eq!(detail.resource, "show interface");
    assert_eq!(detail.path, "$.priority");
    handle.shutdown().await?;
    Ok(())
}

/// A mistyped static lease is `UnreadableAnswer` naming `show rc ip dhcp host`.
#[tokio::test]
async fn a_mistyped_static_lease_is_unreadable() -> TestResult {
    let _trace = TraceCapture::install();
    let (context, handle) = router(
        PROFILES[0],
        &[],
        FaultInjection::default().rc_override("/ip/dhcp/host", json!([{ "mac": 5_i32 }])),
        "r8",
    )
    .await?;

    let (_text, detail) = unreadable(dhcp::read_static_leases(&context).await)?;

    assert_eq!(detail.resource, "show rc ip dhcp host");
    assert_eq!(detail.path, "$[0].mac");
    handle.shutdown().await?;
    Ok(())
}

/// A mistyped router user is `UnreadableAnswer` naming `show rc user`.
#[tokio::test]
async fn a_mistyped_router_user_is_unreadable() -> TestResult {
    let _trace = TraceCapture::install();
    let (context, handle) = router(
        PROFILES[0],
        &[],
        FaultInjection::default().rc_override("/user", json!([{ "tag": 5_i32 }])),
        "r9",
    )
    .await?;

    let (_text, detail) = unreadable(router_users::read_users(&context).await)?;

    assert_eq!(detail.resource, "show rc user");
    assert!(detail.path.starts_with("$.user[0]"), "{}", detail.path);
    handle.shutdown().await?;
    Ok(())
}
