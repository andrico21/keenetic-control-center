//! Argument strategies: well-shaped, malformed, and boundary JSON for every tool input.

use proptest::{option, prelude::*};
use serde_json::{Value, json};

pub(super) fn arbitrary_text() -> BoxedStrategy<String> {
    prop_oneof![
        any::<String>(),
        Just(String::new()),
        Just("lab-1".to_owned()),
        Just("\0control\n".to_owned()),
        Just("\u{440}\u{43e}\u{443}\u{442}\u{435}\u{440}-\u{1f680}".to_owned()),
        Just("x".repeat(2048)),
    ]
    .boxed()
}

pub(super) fn arbitrary_json() -> BoxedStrategy<Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        arbitrary_text().prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map(".{0,32}", inner, 0..6)
                .prop_map(|items| Value::Object(items.into_iter().collect())),
        ]
    })
    .boxed()
}

pub(super) fn arbitrary_fields() -> BoxedStrategy<Option<Vec<String>>> {
    option::of(prop::collection::vec(arbitrary_text(), 0..20)).boxed()
}

pub(super) fn list_arguments() -> BoxedStrategy<Value> {
    let shaped = (
        option::of(arbitrary_text()),
        option::of(any::<u16>()),
        arbitrary_fields(),
    )
        .prop_map(
            |(cursor, limit, fields)| json!({"cursor": cursor, "limit": limit, "fields": fields}),
        );
    prop_oneof![
        6 => shaped,
        1 => arbitrary_json(),
        1 => Just(json!({"cursor": [], "unknown": true})),
    ]
    .boxed()
}

pub(super) fn host_arguments() -> BoxedStrategy<Value> {
    prop_oneof![
        6 => arbitrary_text().prop_map(|host| json!({"host": host})),
        1 => arbitrary_json(),
        1 => Just(json!({})),
        1 => Just(json!({"host": 7, "unknown": true})),
    ]
    .boxed()
}

pub(super) fn catalog_search_arguments() -> BoxedStrategy<Value> {
    let shaped = (
        arbitrary_text(),
        arbitrary_text(),
        option::of(any::<u16>()),
        option::of(arbitrary_text()),
        arbitrary_fields(),
    )
        .prop_map(|(host, query, limit, cursor, fields)| {
            json!({
                "host": host,
                "query": query,
                "limit": limit,
                "cursor": cursor,
                "fields": fields
            })
        });
    prop_oneof![
        6 => shaped,
        1 => arbitrary_json(),
        1 => Just(json!({"host": "lab-1"})),
        1 => Just(json!({"host": [], "query": false})),
    ]
    .boxed()
}

pub(super) fn catalog_describe_arguments() -> BoxedStrategy<Value> {
    prop_oneof![
        6 => (arbitrary_text(), arbitrary_text())
            .prop_map(|(host, path)| json!({"host": host, "path": path})),
        1 => arbitrary_json(),
        1 => Just(json!({"host": "lab-1"})),
        1 => Just(json!({"host": true, "path": []})),
    ]
    .boxed()
}

pub(super) fn rci_read_arguments() -> BoxedStrategy<Value> {
    let shaped = (
        arbitrary_text(),
        arbitrary_text(),
        prop::collection::vec(arbitrary_text(), 0..20),
        arbitrary_json(),
        Just("get"),
        arbitrary_fields(),
    )
        .prop_map(|(host, catalog_path, path, value, kind, fields)| {
            json!({
                "host": host,
                "catalog_path": catalog_path,
                "path": path,
                "value": value,
                "kind": kind,
                "fields": fields
            })
        });
    prop_oneof![
        6 => shaped,
        1 => arbitrary_json(),
        1 => Just(json!({"host": "lab-1", "catalog_path": "show version"})),
        1 => Just(json!({
            "host": [], "catalog_path": 1, "path": false, "kind": "other"
        })),
    ]
    .boxed()
}

pub(super) fn rci_write_arguments() -> BoxedStrategy<Value> {
    let shaped = (
        arbitrary_text(),
        arbitrary_text(),
        prop::collection::vec(arbitrary_text(), 0..20),
        arbitrary_json(),
        any::<bool>(),
    )
        .prop_map(|(host, catalog_path, path, value, confirm)| {
            json!({
                "host": host,
                "catalog_path": catalog_path,
                "path": path,
                "value": value,
                "confirm": confirm
            })
        });
    prop_oneof![
        6 => shaped,
        1 => arbitrary_json(),
        1 => Just(json!({"host": "lab-1", "path": []})),
        1 => Just(json!({
            "host": {}, "catalog_path": [], "path": "system", "confirm": 1
        })),
    ]
    .boxed()
}

pub(super) fn rci_batch_arguments() -> BoxedStrategy<Value> {
    let shaped = (
        arbitrary_text(),
        prop::collection::vec(arbitrary_json(), 0..20),
        any::<bool>(),
    )
        .prop_map(
            |(host, items, confirm)| json!({"host": host, "items": items, "confirm": confirm}),
        );
    prop_oneof![
        6 => shaped,
        1 => arbitrary_json(),
        1 => Just(json!({"host": "lab-1"})),
        1 => Just(json!({"host": 1, "items": {}, "confirm": "yes"})),
    ]
    .boxed()
}

pub(super) fn cli_arguments() -> BoxedStrategy<Value> {
    prop_oneof![
        6 => (arbitrary_text(), arbitrary_text(), any::<bool>())
            .prop_map(|(host, line, confirm)| {
                json!({"host": host, "line": line, "confirm": confirm})
            }),
        1 => arbitrary_json(),
        1 => Just(json!({"host": "lab-1"})),
        1 => Just(json!({"host": [], "line": {}, "confirm": null})),
    ]
    .boxed()
}

pub(super) fn job_arguments() -> BoxedStrategy<Value> {
    prop_oneof![
        6 => arbitrary_text().prop_map(|id| json!({"id": id})),
        1 => arbitrary_json(),
        1 => Just(json!({})),
        1 => Just(json!({"id": [], "unknown": true})),
    ]
    .boxed()
}

/// Arguments for the registry-generated tools: plausible hosts and operations mixed with
/// arbitrary values.
pub(super) fn generated_arguments() -> BoxedStrategy<Value> {
    let ops = prop_oneof![
        Just("version".to_owned()),
        Just("list".to_owned()),
        Just("hostname".to_owned()),
        Just("reboot".to_owned()),
        Just("factory_reset".to_owned()),
        Just("ipv4_route".to_owned()),
        Just("ping".to_owned()),
        arbitrary_text(),
    ];
    let shaped = (arbitrary_text(), ops, any::<bool>(), option::of(arbitrary_text()))
        .prop_map(|(host, op, confirm, value)| {
            json!({"host": host, "op": op, "confirm": confirm, "value": value})
        });
    let migration = (arbitrary_text(), arbitrary_text(), any::<bool>()).prop_map(
        |(host, plan_id, confirm)| json!({"host": host, "plan_id": plan_id, "confirm": confirm}),
    );
    prop_oneof![
        4 => shaped,
        2 => migration,
        1 => arbitrary_json(),
        1 => Just(json!({"host": "lab-1", "op": "version"})),
    ]
    .boxed()
}
