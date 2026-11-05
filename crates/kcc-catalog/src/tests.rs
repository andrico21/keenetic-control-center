//! Catalog runtime acceptance and property tests.

use core::{str::FromStr as _, time::Duration};

use kcc_rci::{
    OutboundPolicy, RciClient, RciClientOptions, RciError, RciPath, RouterUrl, auth::Credentials,
    version::FirmwareVersion,
};
use kcc_testkit::{DEFAULT_LOGIN, DEFAULT_PASSWORD, FakeRouter};
use proptest::prelude::*;
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::{
    Catalog, CatalogVersion, HttpMethod, ModelMatch, RawAuthorization, RequestOptions, Risk,
    ValidationIssue,
};

/// Builds an exact KN-1811 catalog for a firmware title.
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn catalog(title: &str) -> Catalog {
    Catalog::for_firmware_and_model(
        FirmwareVersion::from_str(title).expect("test firmware is valid"),
        Some("KN-1811"),
    )
    .expect("generated catalog is valid")
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn selects_newest_compatible_firmware_and_model_view() {
    let cases = [
        ("4.3.9", CatalogVersion::V4_3),
        ("5.0.12", CatalogVersion::V5_0),
        ("5.2 Beta 2", CatalogVersion::V5_1),
    ];
    for (title, expected) in cases {
        assert_eq!(catalog(title).version(), expected, "firmware case {title}");
    }
    assert!(
        matches!(catalog("5.1.0").model_match(), ModelMatch::Exact(model) if model == "KN-1811")
    );
    let union = Catalog::for_firmware_and_model(
        FirmwareVersion::from_str("5.1.0").expect("test firmware is valid"),
        Some("NC-3013"),
    )
    .expect("generated catalog is valid");
    assert_eq!(union.model_match(), &ModelMatch::Union);
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn version_views_include_only_commands_available_on_that_line() {
    let v4 = catalog("4.3.9");
    let v5 = catalog("5.0.12");
    let v51 = catalog("5.1.0");
    for current in [&v4, &v5, &v51] {
        assert!(current.lookup("show version").is_some());
        assert!(current.lookup("show interface").is_some());
    }
    assert!(v4.lookup("ipv6 access-list").is_none());
    let introduced_in_51 = v51
        .commands()
        .find(|command| v5.lookup(&command.path).is_none())
        .expect("5.1 adds at least one command");
    assert!(v5.lookup(&introduced_in_51.path).is_none());
    drop(
        v51.validate("system configuration save", HttpMethod::Post, &json!({}))
            .expect("save is accepted by every firmware view"),
    );
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn rejects_incident_positional_array_without_panicking() {
    let issues = catalog("5.1.0")
        .validate(
            "",
            HttpMethod::Post,
            &json!({"ip":{"route":["10.0.5.0","255.255.255.255","Wireguard2"]}}),
        )
        .expect_err("positional route payload must be rejected");
    assert!(issues.iter().any(|issue| matches!(
        issue,
        ValidationIssue::ExpectedObject { field } if field == "ip.route"
    )));
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn rejects_silent_noop_field_and_accepts_both_keyword_forms() {
    let catalog = catalog("5.1.0");
    let issues = catalog
        .validate(
            "",
            HttpMethod::Post,
            &json!({"ip":{"hotspot":{"host":{"mac":"02:00:00:00:00:01","name":"x"}}}}),
        )
        .expect_err("known-host name must not be accepted by hotspot host");
    assert!(issues.iter().any(|issue| matches!(
        issue,
        ValidationIssue::UnknownField { field, suggestion: _ } if field == "ip.hotspot.host.name"
    )));
    drop(
        catalog
            .validate(
                "",
                HttpMethod::Post,
                &json!({"ip":{"hotspot":{"host":{"mac":"02:00:00:00:00:01","access":"permit"}}}}),
            )
            .expect("keyword string form is accepted"),
    );
    drop(
        catalog
            .validate(
                "",
                HttpMethod::Post,
                &json!({"ip":{"hotspot":{"host":{"mac":"02:00:00:00:00:01","permit":true}}}}),
            )
            .expect("keyword boolean form is accepted"),
    );
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn enforces_methods_background_lifecycle_and_risk() {
    let catalog = catalog("5.1.0");
    assert!(matches!(
        catalog.validate("system", HttpMethod::Delete, &json!({})),
        Err(issues) if issues.contains(&ValidationIssue::MethodNotAllowed { method: HttpMethod::Delete })
    ));
    for method in [HttpMethod::Post, HttpMethod::Get, HttpMethod::Delete] {
        drop(
            catalog
                .validate("tools ping", method, &json!({}))
                .expect("every background lifecycle method is accepted"),
        );
    }
    assert_eq!(
        catalog.risk("system configuration factory-reset"),
        Some(Risk::Destructive)
    );
    catalog.learn_background("system");
    drop(
        catalog
            .validate("system", HttpMethod::Get, &json!({}))
            .expect("runtime-learned background command accepts polling"),
    );
}

#[test]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions define the contract"
)]
fn search_uses_project_synonyms() {
    let catalog = catalog("5.1.0");
    let results = catalog.search("port forwarding", 3);
    assert!(
        results
            .iter()
            .any(|result| result.command.path == "ip static"),
        "top results: {results:?}"
    );
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn raw_escape_requires_both_administrator_capabilities() {
    let catalog = catalog("5.2 Beta 2");
    let options = RequestOptions {
        unvalidated: true,
        authorization: RawAuthorization {
            raw_rci: true,
            admin_manage_routers: true,
        },
    };
    drop(
        catalog
            .validate("future command", HttpMethod::Post, &json!({}))
            .expect_err("unknown command is rejected without the raw escape"),
    );
    let request = catalog
        .validate_with_options("future command", HttpMethod::Post, &json!({}), options)
        .expect("administrator raw request is accepted");
    assert!(request.unvalidated);
    drop(
        catalog
            .validate_with_options(
                "future command",
                HttpMethod::Post,
                &json!({}),
                RequestOptions {
                    unvalidated: true,
                    authorization: RawAuthorization {
                        raw_rci: true,
                        admin_manage_routers: false,
                    },
                },
            )
            .expect_err("raw escape requires both administrator capabilities"),
    );
}

#[test]
#[expect(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "test fixtures and assertions are expected to be valid"
)]
fn every_generated_schema_has_draft_object_structure() {
    for current in [catalog("4.3.9"), catalog("5.0.12"), catalog("5.1.0")] {
        for command in current.commands() {
            let schema = current
                .to_json_schema(&command.path)
                .expect("visible command has a schema");
            assert_eq!(
                schema.get("$schema").and_then(Value::as_str),
                Some("https://json-schema.org/draft/2020-12/schema")
            );
            assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
            assert!(schema.get("properties").is_some_and(Value::is_object));
            assert_eq!(
                schema.get("additionalProperties").and_then(Value::as_bool),
                Some(false)
            );
        }
    }
}

/// Generates bounded arbitrary JSON trees for the no-panic boundary property.
fn arbitrary_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        ".{0,32}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(Value::Array),
            prop::collection::btree_map("[a-z-]{1,12}", inner, 0..8)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

proptest! {
    #[test]
    fn validate_never_panics_on_arbitrary_json(value in arbitrary_json()) {
        let _result = catalog("5.1.0").validate("ip hotspot host", HttpMethod::Post, &value);
    }
}

#[tokio::test]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[expect(
    clippy::expect_used,
    reason = "test fixtures and assertions are expected to be valid"
)]
async fn background_command_runs_and_cancels_through_validated_engine() -> Result<(), RciError> {
    let catalog = catalog("5.1.0");
    let body = json!({"host":"192.0.2.1"});
    let request = catalog
        .validate("tools ping", HttpMethod::Post, &body)
        .expect("catalog accepts background start");
    let (address, handle) = FakeRouter::spawn()
        .await
        .map_err(|_error| RciError::Transport)?;
    let router =
        RouterUrl::from_str(&format!("http://{address}")).map_err(|_error| RciError::Validation)?;
    let credentials = Credentials::new(
        DEFAULT_LOGIN.to_owned(),
        SecretString::from(DEFAULT_PASSWORD.to_owned()),
    );
    let options =
        RciClientOptions::default().with_outbound(OutboundPolicy::default().with_loopback(true));
    let client = RciClient::connect_with(router, credentials, options).await?;
    let path = RciPath::from_segments(["tools", "ping"]).map_err(|_error| RciError::Validation)?;
    let process = client
        .start(path.clone(), &request.value)
        .await?
        .with_poll_interval(Duration::from_millis(1));
    drop(
        catalog
            .validate("tools ping", HttpMethod::Get, &json!({}))
            .expect("catalog accepts background poll"),
    );
    drop(process.poll(&CancellationToken::new()).await?);

    let cancellation = client
        .start(path, &body)
        .await?
        .with_poll_interval(Duration::from_secs(60));
    drop(
        catalog
            .validate("tools ping", HttpMethod::Delete, &json!({}))
            .expect("catalog accepts background stop"),
    );
    let token = CancellationToken::new();
    token.cancel();
    assert!(matches!(
        cancellation.poll(&token).await,
        Err(RciError::Timeout)
    ));
    handle
        .shutdown()
        .await
        .map_err(|_error| RciError::Transport)?;
    Ok(())
}
