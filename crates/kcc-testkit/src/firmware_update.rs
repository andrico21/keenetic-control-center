//! The firmware a fake router offers to `components check-update`.
//!
//! Off by default: an unconfigured router keeps answering the command as an unknown
//! command, as before. [`crate::FakeRouter::with_firmware_update`] opts in.

use serde_json::{Value, json};

use crate::tree;

/// What `components check-update` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FirmwareUpdate {
    /// Newer firmware with this title is available.
    Available(String),
    /// The router runs the newest firmware of its channel.
    Current,
}

impl FirmwareUpdate {
    /// The parser answer: the status line plus `available` and, when available, the
    /// offered `version`; **assumed (not live-verified)**.
    pub(crate) fn answer(&self) -> Value {
        match self {
            Self::Available(version) => {
                let mut answer =
                    tree::status("message", &format!("firmware {version} is available."));
                if let Some(fields) = answer.as_object_mut() {
                    drop(fields.insert("available".to_owned(), Value::Bool(true)));
                    drop(fields.insert("version".to_owned(), json!(version)));
                }
                answer
            }
            Self::Current => {
                let mut answer = tree::status("message", "no updates available.");
                if let Some(fields) = answer.as_object_mut() {
                    drop(fields.insert("available".to_owned(), Value::Bool(false)));
                }
                answer
            }
        }
    }
}
