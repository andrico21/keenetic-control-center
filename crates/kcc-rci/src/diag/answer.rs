//! Value-free details of router answers kcc could not read.

use core::fmt;

use serde::de::DeserializeOwned;
use serde_json::{Value, error::Category};
use serde_path_to_error::Segment;

/// Longest `expected` text kept from a decoder message, in characters.
const EXPECTED_CHARS: usize = 80;

/// Longest map key or field name shown in a path, in characters.
const NAME_CHARS: usize = 64;

/// Which answer could not be read, where, and why; never a router value.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DecodeDetail {
    /// kcc's words for the answer, such as `show version`.
    pub resource: String,
    /// Where in the answer: `$`, then `[n]` per index and `.key` per field; a key that
    /// is not a plain name is `.*`, an unknown segment `.?`.
    pub path: String,
    /// What was wrong there.
    pub problem: DecodeProblem,
}

/// What was wrong with an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeProblem {
    /// The body is not JSON.
    NotJson {
        /// Body length.
        bytes: usize,
        /// Whether the body starts like HTML.
        html: bool,
    },
    /// The body is neither JSON nor UTF-8 text.
    NotUtf8 {
        /// Body length.
        bytes: usize,
    },
    /// A value has another JSON kind than kcc expects.
    Mismatch {
        /// The JSON kind found at the path.
        found: JsonKind,
        /// What kcc's decoder expected, in its own words.
        expected: String,
    },
    /// A field kcc requires is missing.
    Missing {
        /// kcc's name of the field.
        field: String,
    },
    /// One of kcc's own JSON pointers is absent from the answer.
    MissingPointer {
        /// kcc's pointer, such as `/process/id`.
        pointer: String,
    },
    /// An answer list has another length than the request.
    Length {
        /// Expected number of answers.
        expected: usize,
        /// Number of answers received.
        got: usize,
    },
    /// Another failure, by category.
    Other {
        /// kcc's words for the category.
        category: &'static str,
    },
}

/// The kind of a JSON value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonKind {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool,
    /// A number.
    Number,
    /// A string.
    String,
    /// An array.
    Array,
    /// An object.
    Object,
    /// No value at the path.
    Absent,
}

impl DecodeDetail {
    /// A detail of `resource` at `path`.
    #[inline]
    #[must_use]
    #[expect(
        clippy::unnecessary_box_returns,
        reason = "`RciError::Decode` holds the detail boxed to keep every result small"
    )]
    pub fn new(resource: &str, path: &str, problem: DecodeProblem) -> Box<Self> {
        Box::new(Self {
            resource: resource.to_owned(),
            path: path.to_owned(),
            problem,
        })
    }
}

impl JsonKind {
    /// The kind of `value`, or [`JsonKind::Absent`] without one.
    #[inline]
    #[must_use]
    pub const fn of(value: Option<&Value>) -> Self {
        match value {
            None => Self::Absent,
            Some(Value::Null) => Self::Null,
            Some(Value::Bool(_)) => Self::Bool,
            Some(Value::Number(_)) => Self::Number,
            Some(Value::String(_)) => Self::String,
            Some(Value::Array(_)) => Self::Array,
            Some(Value::Object(_)) => Self::Object,
        }
    }
}

impl fmt::Display for JsonKind {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "null",
            Self::Bool => "boolean",
            Self::Number => "number",
            Self::String => "string",
            Self::Array => "array",
            Self::Object => "object",
            Self::Absent => "nothing",
        })
    }
}

impl fmt::Display for DecodeDetail {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            resource,
            path,
            problem,
        } = self;
        match problem {
            DecodeProblem::Mismatch { found, expected } => {
                write!(
                    f,
                    "{resource} at {path}: found {found}, expected {expected}"
                )
            }
            DecodeProblem::Missing { field } => {
                write!(f, "{resource} at {path}: missing field {field}")
            }
            DecodeProblem::NotJson { bytes, html } => {
                let suffix = if *html { ", HTML" } else { "" };
                write!(f, "{resource}: not JSON ({bytes} bytes{suffix})")
            }
            DecodeProblem::NotUtf8 { bytes } => write!(f, "{resource}: not UTF-8 ({bytes} bytes)"),
            DecodeProblem::MissingPointer { pointer } => {
                write!(f, "{resource}: no {pointer} in the answer")
            }
            DecodeProblem::Length { expected, got } => {
                write!(f, "{resource}: expected {expected} answers, got {got}")
            }
            DecodeProblem::Other { category } => write!(f, "{resource} at {path}: {category}"),
        }
    }
}

/// Decodes `value` as `T`, naming the failing path and kinds but never a router value.
///
/// # Errors
///
/// Returns the detail of the first value that does not fit `T`.
#[inline]
pub fn decode_value<T>(resource: &str, value: &Value) -> Result<T, Box<DecodeDetail>>
where
    T: DeserializeOwned,
{
    serde_path_to_error::deserialize(value).map_err(|error| {
        let segments = error.path().iter().collect::<Vec<_>>();
        let path = render(&segments);
        let message = error.inner().to_string();
        let problem = match (missing_field(&message), message.rsplit_once("expected ")) {
            (Some(field), _) => DecodeProblem::Missing { field },
            (None, Some((_before, expected))) => DecodeProblem::Mismatch {
                found: JsonKind::of(locate(value, &segments)),
                expected: expected.chars().take(EXPECTED_CHARS).collect(),
            },
            (None, None) => DecodeProblem::Other {
                category: category(error.inner().classify()),
            },
        };
        DecodeDetail::new(resource, &path, problem)
    })
}

/// The detail of a body that is not JSON.
#[inline]
#[must_use]
#[expect(
    clippy::unnecessary_box_returns,
    reason = "`RciError::Decode` holds the detail boxed to keep every result small"
)]
pub fn not_json(resource: &str, body: &[u8]) -> Box<DecodeDetail> {
    let html = body
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'<');
    DecodeDetail::new(
        resource,
        "$",
        DecodeProblem::NotJson {
            bytes: body.len(),
            html,
        },
    )
}

/// kcc's field name of a `missing field` message.
fn missing_field(message: &str) -> Option<String> {
    let rest = message.strip_prefix("missing field `")?;
    let (field, _after) = rest.split_once('`')?;
    Some(field.chars().take(NAME_CHARS).collect())
}

/// The words of a decoder failure category.
const fn category(category: Category) -> &'static str {
    match category {
        Category::Io => "io",
        Category::Syntax => "syntax",
        Category::Data => "data",
        Category::Eof => "eof",
    }
}

/// Renders `segments` with every key that is not a plain name masked.
fn render(segments: &[&Segment]) -> String {
    let mut path = String::from("$");
    for segment in segments {
        match segment {
            Segment::Seq { index } => {
                path.push('[');
                path.push_str(&index.to_string());
                path.push(']');
            }
            Segment::Map { key } | Segment::Enum { variant: key } => {
                path.push('.');
                path.push_str(if plain_name(key) { key } else { "*" });
            }
            Segment::Unknown => path.push_str(".?"),
        }
    }
    path
}

/// Whether `key` matches `^[A-Za-z][A-Za-z0-9_-]{0,63}$`.
fn plain_name(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && key.len() <= NAME_CHARS
        && chars.all(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '-'))
}

/// The value at the unmasked `segments` of `value`, if any.
fn locate<'value>(value: &'value Value, segments: &[&Segment]) -> Option<&'value Value> {
    segments
        .iter()
        .try_fold(value, |current, segment| match segment {
            Segment::Seq { index } => current.get(*index),
            Segment::Map { key } | Segment::Enum { variant: key } => current.get(key.as_str()),
            Segment::Unknown => None,
        })
}
