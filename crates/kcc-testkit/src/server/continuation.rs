//! Session continuation of background commands, as KN-1811 on 5.1.10 answers them.
//!
//! The POST answers the first output chunk, and each `GET` of the same resource without a
//! query in the same session answers the next one; signing the session out ends the command.

use alloc::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{Value, json};

use super::lock;

/// The resource of `components list`, which continues once and then answers the list.
pub(super) const COMPONENTS: &str = "components/list";

/// The command a session continues at one resource.
#[derive(Clone, Debug)]
pub(super) enum Running {
    /// A simulated process and the number of output lines answered so far.
    Process {
        /// The simulated process id.
        id: String,
        /// Output lines answered so far.
        lines: u32,
    },
    /// `components list`, whose next answer is the list.
    Components,
}

/// The continued commands by session id and resource path.
#[derive(Debug, Default)]
pub(super) struct Continuations(Mutex<BTreeMap<(String, String), Running>>);

impl Continuations {
    /// Binds `running` to `path` in `session`; returns the command it replaces there (a
    /// second POST restarts the command).
    pub(super) fn bind(&self, session: String, path: &str, running: Running) -> Option<Running> {
        lock(&self.0).insert((session, path.trim_end_matches('/').to_owned()), running)
    }

    /// The command `session` continues at `path`.
    pub(super) fn get(&self, session: &str, path: &str) -> Option<Running> {
        lock(&self.0)
            .get(&(session.to_owned(), path.to_owned()))
            .cloned()
    }

    /// Ends the command `session` continues at `path`.
    pub(super) fn finish(&self, session: &str, path: &str) {
        drop(lock(&self.0).remove(&(session.to_owned(), path.to_owned())));
    }

    /// Ends every command of `session` (it signed out) and returns them.
    pub(super) fn end(&self, session: &str) -> Vec<Running> {
        let mut continued = lock(&self.0);
        let keys: Vec<(String, String)> = continued
            .keys()
            .filter(|(owner, _path)| owner == session)
            .cloned()
            .collect();
        let ended = keys
            .iter()
            .filter_map(|key| continued.remove(key))
            .collect();
        drop(continued);
        ended
    }
}

/// One output chunk of the tool `name`: `count` lines numbered from `first`, marked
/// `continued` unless it is the `last`.
pub(super) fn message_chunk(name: &str, first: u32, count: u32, last: bool) -> Value {
    let message: Vec<String> = (first..first.saturating_add(count))
        .map(|line| format!("{name}: output line {line}"))
        .collect();
    if last {
        json!({"message": message})
    } else {
        json!({"message": message, "continued": true})
    }
}
