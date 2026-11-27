//! Replayed router answers: continued exchanges and, in replay mode, verbatim `show` and
//! `show rc` answers taken from the builder's fixtures only.

use alloc::collections::BTreeMap;
use std::sync::Mutex;

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use serde_json::{Map, Value};

use super::{empty, lock, set_pointer};
use crate::tree;

/// Captured answers the fake replays.
#[derive(Debug, Default)]
pub(super) struct Replay {
    /// Verbatim `show` answers keyed by the path below `show/`; `None` outside replay mode.
    show: Option<Map<String, Value>>,
    /// The `show rc` tree built from the `rc_fixture` roots; `None` outside replay mode.
    rc: Option<Value>,
    /// The answers of each continued exchange, keyed by resource path.
    continued: BTreeMap<String, Vec<Value>>,
    /// The index of the next answer per resource path and session id.
    cursors: Mutex<BTreeMap<(String, String), usize>>,
}

impl Replay {
    /// Replays `continued`; with `verbatim` (the `show` fixtures by path) the fake also
    /// answers `show` only from those and `show rc` only from `roots` (by JSON pointer).
    pub(super) fn new(
        continued: BTreeMap<String, Vec<Value>>,
        verbatim: Option<Map<String, Value>>,
        roots: &Map<String, Value>,
    ) -> Self {
        let rc = verbatim.is_some().then(|| {
            let mut tree = Value::Object(Map::new());
            for (pointer, value) in roots {
                set_pointer(&mut tree, pointer, value.clone());
            }
            tree
        });
        Self {
            show: verbatim,
            rc,
            continued,
            cursors: Mutex::default(),
        }
    }

    /// The first answer of the continued exchange at `path`, which (re)starts it for
    /// `session`; `None` when `path` has no continued fixture.
    pub(super) fn start(&self, path: &str, session: Option<String>) -> Option<Response> {
        let key = path.trim_end_matches('/');
        let first = self.continued.get(key)?.first()?;
        if let Some(id) = session {
            let _restarted: Option<usize> = lock(&self.cursors).insert((key.to_owned(), id), 1);
        }
        Some(answer(first))
    }

    /// The next answer of the exchange `session` started at `path` (the last one repeats),
    /// 404 when it started none; `None` when `path` has no continued fixture.
    pub(super) fn next(&self, path: &str, session: Option<String>) -> Option<Response> {
        let key = path.trim_end_matches('/');
        let answers = self.continued.get(key)?;
        let Some(id) = session else {
            return Some(empty(StatusCode::NOT_FOUND));
        };
        let mut cursors = lock(&self.cursors);
        let Some(index) = cursors.get_mut(&(key.to_owned(), id)) else {
            return Some(empty(StatusCode::NOT_FOUND));
        };
        let found = answers.get(*index).or_else(|| answers.last());
        *index = index.saturating_add(1);
        drop(cursors);
        Some(found.map_or_else(|| empty(StatusCode::NOT_FOUND), answer))
    }

    /// In replay mode, the verbatim `show` answers by path below `show/`.
    pub(super) const fn verbatim(&self) -> Option<&Map<String, Value>> {
        self.show.as_ref()
    }

    /// In replay mode, the `show rc` answer to `request` from the fixture roots only.
    pub(super) fn rc(&self, request: &Value) -> Option<Value> {
        self.rc
            .as_ref()
            .map(|roots| tree::read_through(roots, request))
    }
}

/// A captured answer: a string as plain text (the capture records a text answer so),
/// anything else as JSON.
fn answer(value: &Value) -> Response {
    match value {
        Value::String(text) => text.clone().into_response(),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
            Json(value.clone()).into_response()
        }
    }
}
