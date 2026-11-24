//! The MCP settings at `/ui/admin/mcp` (`ManageMcp`).
//!
//! The page edits the Web-managed `[mcp]` keys of `mcp_settings.json` section by section:
//! tools, endpoints, sign-in per listener, kcc sign-in, the identity provider and client
//! certificates. Every value shows where it comes from; values an environment variable or
//! `[mcp] locked` sets are text only, and a value set here can be reset to kcc.toml.
//!
//! A change is planned with `McpBase::plan_update` as the signed-in role. A change that
//! reduces safety asks for the account's password first (a wrong one counts toward the
//! sign-in lockout). The running listeners ([`McpControl`](crate::admin::McpControl))
//! apply and save it: at once when it restarts no listener, otherwise in the background
//! while the page polls the restart's outcome.

extern crate alloc;

mod assign;
pub(crate) mod certificate;
mod flow;
mod form;
mod keyed;
mod messages;
pub(crate) mod page;
mod pem;
mod reply;
mod rows;
pub(crate) mod save;
mod sections;
pub(crate) mod status;
pub(crate) mod upload;
mod view;

use alloc::sync::Arc;
use std::sync::{Mutex, PoisonError};

use kcc_app::mcp_settings::ListenerKind;
use secrecy::SecretString;

use crate::admin::{
    McpControl,
    issuer::Issuer,
    mcp_control::{McpRefusal, McpStatus, McpToolset},
};

/// The running listeners and the latest restart the page asked for.
pub(crate) struct Attached {
    /// The running listeners.
    control: Arc<dyn McpControl>,
    /// The latest restart the page asked for.
    progress: Mutex<Progress>,
}

/// The latest restart the page asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Progress {
    /// None since the start.
    Idle,
    /// Running for these listeners.
    Restarting(Vec<ListenerKind>),
    /// Applied and saved.
    Applied,
    /// Refused or reverted.
    Refused(McpRefusal),
}

impl Attached {
    /// The page's view of `control`, with no restart asked for yet.
    pub(crate) fn new(control: Arc<dyn McpControl>) -> Self {
        Self {
            control,
            progress: Mutex::new(Progress::Idle),
        }
    }

    /// The running listeners.
    pub(crate) fn control(&self) -> &dyn McpControl {
        self.control.as_ref()
    }

    /// The latest restart the page asked for.
    pub(crate) fn progress(&self) -> Progress {
        self.progress
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Records `progress` as the latest restart's.
    pub(crate) fn set_progress(&self, progress: Progress) {
        *self.progress.lock().unwrap_or_else(PoisonError::into_inner) = progress;
    }
}

/// How a setting is edited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Control {
    /// A checkbox.
    Check(bool),
    /// A one-line text field of the input type (`text` or `number`).
    Text(String, &'static str),
    /// A drop-down list.
    Select(Vec<Choice>),
    /// A list of checkboxes.
    Checks(Vec<Choice>),
    /// Rows of a value and a role.
    Mappings(Mappings),
}

/// One option of a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Choice {
    /// The posted value.
    value: String,
    /// What the option says.
    label: String,
    /// Whether it is the current value.
    chosen: bool,
    /// Whether choosing it reduces safety.
    reduces: bool,
}

impl Choice {
    /// The option `value` saying `label`, chosen when `chosen`.
    pub(crate) const fn new(value: String, label: String, chosen: bool) -> Self {
        Self {
            value,
            label,
            chosen,
            reduces: false,
        }
    }
}

/// A table of value-to-role rows with one blank row to add another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mappings {
    /// The posted name of the first column.
    first: &'static str,
    /// The posted name of the role column.
    second: &'static str,
    /// The first column's header.
    heading: String,
    /// The rows, the blank one last.
    rows: Vec<(String, String)>,
    /// Every role a row may name.
    roles: Vec<String>,
}

/// One setting of a section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    /// The key path, also the posted name.
    name: &'static str,
    /// The element id.
    id: String,
    /// The label.
    label: String,
    /// Where the value comes from.
    source: String,
    /// Whether the environment or `[mcp] locked` sets it: text only.
    fixed: bool,
    /// The value as text, for a fixed setting.
    shown: String,
    /// Whether the value was set on the Web and can be reset to kcc.toml here.
    reset: bool,
    /// How it is edited.
    control: Control,
}

/// What the region shows beside the settings.
pub(crate) struct Facts {
    /// The running listeners' start-up status; `None` when no listener runs here.
    status: Option<McpStatus>,
    /// Every toolset the MCP server offers.
    toolsets: Vec<McpToolset>,
    /// Every role name.
    roles: Vec<String>,
    /// The roles the signed-in role dominates, which it may name as the client-certificate
    /// default role.
    assignable: Vec<String>,
    /// The issuer of kcc's authorization server, or why it has none.
    issuer: Issuer,
    /// The SHA-256 fingerprint of the self-signed certificate, once made.
    fingerprint: Option<String>,
    /// Whether a client CA and an identity provider CA bundle are stored.
    cas: (bool, bool),
    /// The stored client CA's and identity provider CA bundle's certificate subjects, each
    /// `None` when the file does not pass the checks.
    subjects: (Option<Vec<String>>, Option<Vec<String>>),
    /// The listeners using the client CA and the identity provider CA bundle: replacing
    /// either asks for the password and restarts its listeners.
    users: (Vec<ListenerKind>, Vec<ListenerKind>),
    /// The `mcp_settings.json` revision the region shows; every form posts it back.
    revision: u64,
}

/// How the change was posted: where, with which fields, and the password if typed.
pub(crate) struct Posted<'form> {
    /// Where the form posts, for the password dialog.
    to: &'static str,
    /// The posted fields, carried into the dialog without the password.
    pairs: &'form [(String, String)],
    /// The password typed into the dialog.
    password: Option<&'form SecretString>,
    /// The settings revision the form was rendered from, if it carried one.
    revision: Option<u64>,
}
