//! Lenient decoding helpers for the shapes real routers answer with.
//!
//! The scalar functions are `#[serde(deserialize_with = "...")]` targets that accept the
//! spellings a router uses for the same field (a number or a decimal string, a boolean or
//! `"yes"`). The shape functions turn name-keyed objects and object envelopes into the
//! lists the models decode.
//!
//! Every rejection is built with `invalid_type` or `invalid_value` from a fixed word,
//! never from the router's value and never with `custom`: `kcc_rci::decode_value` keeps
//! the text after the last `expected ` of the message, so a value must never be in it.
//! The shape functions never put a router key into a decode path either: they return
//! lists, so a path reads `$[1].field`.

use serde::{
    Deserialize as _, Deserializer,
    de::{Error, Unexpected},
};
use serde_json::{Map, Value};

/// Reads a scalar with `parse`, or rejects it without naming its content.
///
/// # Errors
///
/// Returns the value-free rejection of [`reject`].
fn read<'de, D, T>(
    deserializer: D,
    parse: fn(&Value) -> Option<T>,
    expected: &'static str,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    parse(&value).ok_or_else(|| reject(&value, expected))
}

/// Like [`read`], with `null` as `None`.
///
/// # Errors
///
/// Returns the value-free rejection of [`reject`].
fn read_opt<'de, D, T>(
    deserializer: D,
    parse: fn(&Value) -> Option<T>,
    expected: &'static str,
) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    parse(&value)
        .map(Some)
        .ok_or_else(|| reject(&value, expected))
}

/// The error for a `value` no parser accepted: only its kind is named.
fn reject<E>(value: &Value, expected: &'static str) -> E
where
    E: Error,
{
    match value {
        Value::String(_) => {
            E::invalid_value(Unexpected::Other("a string of another form"), &expected)
        }
        Value::Number(_) => {
            E::invalid_value(Unexpected::Other("a number of another form"), &expected)
        }
        Value::Null => E::invalid_type(Unexpected::Other("null"), &expected),
        Value::Bool(_) => E::invalid_type(Unexpected::Other("a boolean"), &expected),
        Value::Array(_) => E::invalid_type(Unexpected::Other("an array"), &expected),
        Value::Object(_) => E::invalid_type(Unexpected::Other("an object"), &expected),
    }
}

/// A JSON number or a decimal string as `u64`.
fn parse_unsigned(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

/// A JSON number or a decimal string as `i64`.
fn parse_signed(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

/// A JSON number or a numeric string as a finite `f64`.
fn parse_float(value: &Value) -> Option<f64> {
    let parsed = match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    };
    parsed.filter(|float| float.is_finite())
}

/// A boolean, or the text `true`, `false`, `yes` or `no` in any case.
fn parse_boolean(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(text)
            if text.eq_ignore_ascii_case("true") || text.eq_ignore_ascii_case("yes") =>
        {
            Some(true)
        }
        Value::String(text)
            if text.eq_ignore_ascii_case("false") || text.eq_ignore_ascii_case("no") =>
        {
            Some(false)
        }
        Value::Null | Value::Number(_) | Value::String(_) | Value::Array(_) | Value::Object(_) => {
            None
        }
    }
}

/// A boolean, or a string that is `true` when it is not empty.
const fn parse_presence(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::String(text) => Some(!text.is_empty()),
        Value::Null | Value::Number(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

/// A string, or a number or boolean rendered as text.
fn parse_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Words of the unsigned number rejection.
const UNSIGNED: &str = "an unsigned whole number or its decimal text";
/// Words of the signed number rejection.
const SIGNED: &str = "a whole number or its decimal text";
/// Words of the float rejection.
const FLOAT: &str = "a finite number or its decimal text";
/// Words of the boolean rejection.
const BOOLEAN: &str = "a boolean or the text true, false, yes or no";
/// Words of the presence rejection.
const PRESENCE: &str = "a boolean or a text";
/// Words of the text rejection.
const TEXT: &str = "a text, a number or a boolean";

/// Accepts a JSON number or a decimal string as `u64`.
///
/// A negative or fractional number is an `invalid_value`.
///
/// # Errors
///
/// Returns a value-free `invalid_type` or `invalid_value`.
#[inline]
pub fn number<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    read(deserializer, parse_unsigned, UNSIGNED)
}

/// [`number`] for an optional field; `null` is `None`.
///
/// # Errors
///
/// Returns a value-free `invalid_type` or `invalid_value`.
#[inline]
pub fn opt_number<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    read_opt(deserializer, parse_unsigned, UNSIGNED)
}

/// Accepts a JSON number or a decimal string as `i64`.
///
/// # Errors
///
/// Returns a value-free `invalid_type` or `invalid_value`.
#[inline]
pub fn signed<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    read(deserializer, parse_signed, SIGNED)
}

/// [`signed`] for an optional field; `null` is `None`.
///
/// # Errors
///
/// Returns a value-free `invalid_type` or `invalid_value`.
#[inline]
pub fn opt_signed<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    read_opt(deserializer, parse_signed, SIGNED)
}

/// Accepts a JSON number or a numeric string as `f64`; `NaN` and infinity are refused.
///
/// # Errors
///
/// Returns a value-free `invalid_type` or `invalid_value`.
#[inline]
pub fn float<'de, D>(deserializer: D) -> Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    read(deserializer, parse_float, FLOAT)
}

/// [`float`] for an optional field; `null` is `None`.
///
/// # Errors
///
/// Returns a value-free `invalid_type` or `invalid_value`.
#[inline]
pub fn opt_float<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    read_opt(deserializer, parse_float, FLOAT)
}

/// Accepts a boolean, or the text `true`, `false`, `yes` or `no` in any case.
///
/// # Errors
///
/// Returns a value-free `invalid_type` or `invalid_value`.
#[inline]
pub fn boolean<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    read(deserializer, parse_boolean, BOOLEAN)
}

/// [`boolean`] for an optional field; `null` is `None`.
///
/// # Errors
///
/// Returns a value-free `invalid_type` or `invalid_value`.
#[inline]
pub fn opt_boolean<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    read_opt(deserializer, parse_boolean, BOOLEAN)
}

/// Accepts a boolean, or a string that is `true` when not empty and `false` when empty.
///
/// For fields a router answers with a name when set and an empty string when not (the
/// KeenDNS `booked` field).
///
/// # Errors
///
/// Returns a value-free `invalid_type`.
#[inline]
pub fn boolean_from_text<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    read(deserializer, parse_presence, PRESENCE)
}

/// [`boolean_from_text`] for an optional field; `null` is `None`.
///
/// # Errors
///
/// Returns a value-free `invalid_type`.
#[inline]
pub fn opt_boolean_from_text<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    read_opt(deserializer, parse_presence, PRESENCE)
}

/// Accepts a string, or a number or boolean rendered as text.
///
/// # Errors
///
/// Returns a value-free `invalid_type`.
#[inline]
pub fn text<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    read(deserializer, parse_text, TEXT)
}

/// [`text`] for an optional field; `null` is `None`.
///
/// # Errors
///
/// Returns a value-free `invalid_type`.
#[inline]
pub fn opt_text<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    read_opt(deserializer, parse_text, TEXT)
}

/// Turns a name-keyed object of objects into a list of rows.
///
/// Each entry becomes an object holding the entry's own members plus its key as
/// `name_field`. A member the entry already has under `name_field` wins: the key is added
/// only when absent. Rows follow the iteration order of the JSON map. A list is returned
/// unchanged, and so is anything else (an object with a value that is not an object, a
/// scalar), so the decoder reports the mismatch.
#[inline]
#[must_use]
pub fn keyed_rows(value: &Value, name_field: &str) -> Value {
    let Value::Object(entries) = value else {
        return value.clone();
    };
    if !entries.values().all(Value::is_object) {
        return value.clone();
    }
    let rows = entries
        .iter()
        .map(|(key, entry)| {
            let mut row = entry.as_object().cloned().unwrap_or_default();
            _ = row
                .entry(name_field)
                .or_insert_with(|| Value::String(key.clone()));
            Value::Object(row)
        })
        .collect();
    Value::Array(rows)
}

/// Turns a name-keyed object of scalars (or any values) into rows `{name_field: key,
/// value_field: entry}`, in the iteration order of the JSON map.
///
/// A list is returned unchanged, and so is anything that is not an object.
#[inline]
#[must_use]
pub fn keyed_scalars(value: &Value, name_field: &str, value_field: &str) -> Value {
    let Value::Object(entries) = value else {
        return value.clone();
    };
    let rows = entries
        .iter()
        .map(|(key, entry)| {
            Value::Object(Map::from_iter([
                (name_field.to_owned(), Value::String(key.clone())),
                (value_field.to_owned(), entry.clone()),
            ]))
        })
        .collect();
    Value::Array(rows)
}

/// Accepts the object envelope of a real answer and the bare shape of the previous one.
///
/// An object holding a list or an object under `field` gives that member; a list is
/// returned as is; an empty object (a router's empty list) gives an empty list; anything
/// else is returned unchanged for the decoder to judge.
#[inline]
#[must_use]
pub fn unwrap_envelope(value: &Value, field: &str) -> Value {
    match value {
        Value::Object(members) if members.is_empty() => Value::Array(Vec::new()),
        Value::Object(members) => match members.get(field) {
            Some(inner @ (Value::Array(_) | Value::Object(_))) => inner.clone(),
            Some(_) | None => value.clone(),
        },
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) | Value::Array(_) => {
            value.clone()
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use kcc_rci::{DecodeDetail, DecodeProblem, decode_value};
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    /// One field per lenient flavour.
    #[derive(Debug, Deserialize, PartialEq)]
    struct Scalars {
        #[serde(deserialize_with = "number")]
        unsigned: u64,
        #[serde(deserialize_with = "signed")]
        whole: i64,
        #[serde(deserialize_with = "float")]
        ratio: f64,
        #[serde(deserialize_with = "boolean")]
        flag: bool,
        #[serde(deserialize_with = "boolean_from_text")]
        booked: bool,
        #[serde(deserialize_with = "text")]
        label: String,
    }

    /// One optional field per lenient flavour; every one may be absent.
    #[derive(Debug, Deserialize, PartialEq)]
    struct Optionals {
        #[serde(default, deserialize_with = "opt_number")]
        unsigned: Option<u64>,
        #[serde(default, deserialize_with = "opt_signed")]
        whole: Option<i64>,
        #[serde(default, deserialize_with = "opt_float")]
        ratio: Option<f64>,
        #[serde(default, deserialize_with = "opt_boolean")]
        flag: Option<bool>,
        #[serde(default, deserialize_with = "opt_boolean_from_text")]
        booked: Option<bool>,
        #[serde(default, deserialize_with = "opt_text")]
        label: Option<String>,
    }

    /// A row of a keyed list.
    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Row {
        name: String,
        #[serde(deserialize_with = "number")]
        tag: u64,
    }

    type Decoded<T> = Result<T, Box<DecodeDetail>>;

    fn good() -> Value {
        json!({"unsigned": "7", "whole": -3_i64, "ratio": "2.5", "flag": "Yes",
               "booked": "host-1", "label": 12_u64})
    }

    fn scalars(field: &str, value: &Value) -> Decoded<Scalars> {
        let mut answer = good();
        if let Some(slot) = answer.get_mut(field) {
            *slot = value.clone();
        }
        decode_value("scalar test", &answer)
    }

    fn optionals(field: &str, value: &Value) -> Decoded<Optionals> {
        decode_value("optional test", &json!({ field: value }))
    }

    fn expected_words<T>(result: Decoded<T>) -> Option<String> {
        let DecodeProblem::Mismatch { expected, found: _ } = result.err()?.problem else {
            return None;
        };
        Some(expected)
    }

    fn rows(value: &Value) -> Decoded<Vec<Row>> {
        decode_value("keyed test", &keyed_rows(value, "name"))
    }

    fn texts(detail: &DecodeDetail) -> [String; 2] {
        [format!("{detail}"), format!("{detail:?}")]
    }

    /// todo 13: every flavour accepts the spellings a router uses.
    #[test]
    fn scalars_accept_the_spellings_of_a_router() {
        assert_eq!(
            scalars("flag", &json!("Yes")).ok(),
            Some(Scalars {
                unsigned: 7,
                whole: -3,
                ratio: 2.5,
                flag: true,
                booked: true,
                label: "12".to_owned(),
            })
        );
        let plain = json!({"unsigned": 7_u64, "whole": "-3", "ratio": 2_u64, "flag": false,
                           "booked": "", "label": true});
        assert_eq!(
            decode_value::<Scalars>("scalar test", &plain).ok(),
            Some(Scalars {
                unsigned: 7,
                whole: -3,
                ratio: 2.0,
                flag: false,
                booked: false,
                label: "true".to_owned(),
            })
        );
    }

    /// todo 13: numbers refuse negatives, fractions and words, and name what they expected.
    #[test]
    fn numbers_refuse_what_does_not_fit() {
        let unsigned = [
            json!(-1_i64),
            json!(1.5_f64),
            json!("abc"),
            json!("-1"),
            json!(true),
            json!(null),
        ];
        for bad in unsigned {
            assert_eq!(
                expected_words(scalars("unsigned", &bad)).as_deref(),
                Some(UNSIGNED)
            );
        }
        for bad in [json!(1.5_f64), json!("1.5"), json!([1_u64])] {
            assert_eq!(
                expected_words(scalars("whole", &bad)).as_deref(),
                Some(SIGNED)
            );
        }
        for bad in [json!("infinity"), json!("NaN"), json!("x"), json!({})] {
            assert_eq!(
                expected_words(scalars("ratio", &bad)).as_deref(),
                Some(FLOAT)
            );
        }
    }

    /// todo 13: booleans accept bools and the four words in any case, nothing else.
    #[test]
    fn booleans_accept_four_words_in_any_case() {
        for (word, wanted) in [
            ("TRUE", true),
            ("False", false),
            ("yes", true),
            ("No", false),
        ] {
            assert_eq!(
                scalars("flag", &json!(word)).ok().map(|read| read.flag),
                Some(wanted)
            );
        }
        for bad in [json!("maybe"), json!(1_u64), json!(null), json!([])] {
            assert_eq!(
                expected_words(scalars("flag", &bad)).as_deref(),
                Some(BOOLEAN)
            );
        }
    }

    /// todo 13: a text that is not empty is `true`, an empty one `false`, a number is refused.
    #[test]
    fn presence_texts_follow_emptiness() {
        for (given, wanted) in [(json!("x"), true), (json!(""), false), (json!(true), true)] {
            assert_eq!(
                scalars("booked", &given).ok().map(|read| read.booked),
                Some(wanted)
            );
        }
        assert_eq!(
            expected_words(scalars("booked", &json!(1_u64))).as_deref(),
            Some(PRESENCE)
        );
    }

    /// todo 13: text renders numbers and booleans and refuses containers.
    #[test]
    fn text_renders_scalars() {
        for (given, wanted) in [
            (json!("a b"), "a b"),
            (json!(2.5_f64), "2.5"),
            (json!(false), "false"),
        ] {
            assert_eq!(
                scalars("label", &given)
                    .ok()
                    .map(|read| read.label)
                    .as_deref(),
                Some(wanted)
            );
        }
        for bad in [json!({"a": 1_u64}), json!(null)] {
            assert_eq!(
                expected_words(scalars("label", &bad)).as_deref(),
                Some(TEXT)
            );
        }
    }

    /// todo 13: optional flavours take an absent field and `null` as `None`.
    #[test]
    fn optionals_allow_absent_and_null() {
        let none = Optionals {
            unsigned: None,
            whole: None,
            ratio: None,
            flag: None,
            booked: None,
            label: None,
        };
        assert_eq!(decode_value("optional test", &json!({})).ok(), Some(none));
        assert_eq!(
            optionals("whole", &json!(null)).ok().map(|read| read.whole),
            Some(None)
        );
        let all = json!({"unsigned": "4", "whole": "-2", "ratio": "0.5", "flag": "no",
                         "booked": "", "label": 9_u64});
        assert_eq!(
            decode_value("optional test", &all).ok(),
            Some(Optionals {
                unsigned: Some(4),
                whole: Some(-2),
                ratio: Some(0.5_f64),
                flag: Some(false),
                booked: Some(false),
                label: Some("9".to_owned()),
            })
        );
        assert_eq!(
            expected_words(optionals("unsigned", &json!(-4_i64))).as_deref(),
            Some(UNSIGNED)
        );
        assert_eq!(
            expected_words(optionals("flag", &json!("soon"))).as_deref(),
            Some(BOOLEAN)
        );
    }

    /// todo 13: a router value planted in a mistyped field never shows in the detail.
    #[test]
    fn a_planted_value_never_reaches_the_detail() {
        let planted = "owner-secret-91";
        let attempts = [
            scalars("unsigned", &json!(planted)).err(),
            scalars("whole", &json!(planted)).err(),
            scalars("ratio", &json!(planted)).err(),
            scalars("flag", &json!(planted)).err(),
            scalars("booked", &json!([planted])).err(),
            scalars("label", &json!({"k": planted})).err(),
            scalars("unsigned", &json!(-918_273_i64)).err(),
            scalars("whole", &json!(918.273_f64)).err(),
            optionals("label", &json!([planted])).err(),
            optionals("ratio", &json!(planted)).err(),
        ];
        assert!(attempts.iter().all(Option::is_some));
        for detail in attempts.iter().flatten() {
            for text in texts(detail) {
                for secret in [planted, "918", "273"] {
                    assert!(!text.contains(secret), "{text}");
                }
            }
        }
    }

    /// todo 13: keys move into the name field, an existing member wins, order is the map's.
    #[test]
    fn keyed_rows_move_the_key_into_the_name_field() {
        let value = json!({"alpha": {"tag": 1_u64}, "beta": {"tag": "2", "name": "own"}});
        assert_eq!(
            keyed_rows(&value, "name"),
            json!([{"name": "alpha", "tag": 1_u64}, {"name": "own", "tag": "2"}])
        );
        assert_eq!(
            rows(&value).ok(),
            Some(vec![
                Row {
                    name: "alpha".to_owned(),
                    tag: 1
                },
                Row {
                    name: "own".to_owned(),
                    tag: 2
                },
            ])
        );
    }

    /// todo 13: lists, empty objects and mixed objects keep their shape.
    #[test]
    fn keyed_rows_leave_other_shapes_alone() {
        let list = json!([{"name": "a", "tag": 1_u64}]);
        assert_eq!(keyed_rows(&list, "name"), list);
        assert_eq!(keyed_rows(&json!({}), "name"), json!([]));
        let mixed = json!({"a": {"tag": 1_u64}, "b": true});
        assert_eq!(keyed_rows(&mixed, "name"), mixed);
        assert_eq!(keyed_rows(&json!("x"), "name"), json!("x"));
    }

    /// todo 13: a decode error inside a keyed row carries the index, never the key.
    #[test]
    fn keyed_row_errors_carry_the_index_not_the_key() {
        let key = "owner-like-key";
        let value = json!({"alpha": {"tag": 1_u64}, key: {"tag": "x7"}});
        let detail = rows(&value).err();
        assert_eq!(
            detail.as_ref().map(|found| found.path.as_str()),
            Some("$[1].tag")
        );
        for text in detail.iter().flat_map(|found| texts(found)) {
            assert!(!text.contains(key), "{text}");
        }
    }

    /// todo 13: scalars keyed by name become `{name, value}` rows.
    #[test]
    fn keyed_scalars_make_name_value_rows() {
        let value = json!({"alpha": true, "beta": false});
        assert_eq!(
            keyed_scalars(&value, "name", "value"),
            json!([{"name": "alpha", "value": true}, {"name": "beta", "value": false}])
        );
        let list = json!([1_u64, 2_u64]);
        assert_eq!(keyed_scalars(&list, "name", "value"), list);
        assert_eq!(keyed_scalars(&json!(3_u64), "name", "value"), json!(3_u64));
    }

    /// todo 13: the envelope helper accepts the object envelope and the previous bare shape.
    #[test]
    fn envelopes_unwrap_to_their_member() {
        let list = json!([{"a": 1_u64}]);
        assert_eq!(
            unwrap_envelope(&json!({"host": [{"a": 1_u64}]}), "host"),
            list
        );
        assert_eq!(unwrap_envelope(&list, "host"), list);
        assert_eq!(unwrap_envelope(&json!({}), "host"), json!([]));
        let keyed = json!({"x": {"a": 1_u64}});
        assert_eq!(unwrap_envelope(&json!({"user": keyed}), "user"), keyed);
        let other = json!({"other": [1_u64]});
        assert_eq!(unwrap_envelope(&other, "host"), other);
        let scalar = json!({"host": 5_u64});
        assert_eq!(unwrap_envelope(&scalar, "host"), scalar);
        assert_eq!(unwrap_envelope(&json!("x"), "host"), json!("x"));
    }
}
