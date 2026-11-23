//! A stand-in for the running MCP listeners: it answers every change with a configured
//! refusal or, like the real one, saves the change itself, and records what it was given.

extern crate alloc;

use alloc::sync::Arc;
use std::sync::{Mutex, PoisonError};

use kcc_app::{
    mcp_settings::{Candidate, SettingsError, client_ca::store_mtls_ca, commit},
    persist::StateStore,
};
use kcc_web::admin::{
    McpChange, McpControl,
    mcp_control::{McpRefusal, McpStatus, McpToolset},
};

/// The stand-in.
#[derive(Debug)]
pub(crate) struct Stub {
    /// The state directory a successful change is saved in.
    store: StateStore,
    /// The refusal every change gets; `None` saves it.
    answer: Mutex<Option<McpRefusal>>,
    /// What [`McpControl::status`] reports.
    status: McpStatus,
    /// The candidates [`McpControl::apply_live`] got, in order.
    applied: Mutex<Vec<Candidate>>,
    /// The candidates [`McpControl::restart`] got, in order.
    restarted: Mutex<Vec<Candidate>>,
    /// Whether each [`McpControl::replace_client_ca`] was confirmed, in order.
    replaced: Mutex<Vec<bool>>,
}

impl Stub {
    /// A stand-in saving into `store` and reporting `status`.
    pub(crate) fn new(store: StateStore, status: McpStatus) -> Arc<Self> {
        Arc::new(Self {
            store,
            answer: Mutex::new(None),
            status,
            applied: Mutex::new(Vec::new()),
            restarted: Mutex::new(Vec::new()),
            replaced: Mutex::new(Vec::new()),
        })
    }

    /// Answers every later change with `refusal`, or saves it when `None`.
    pub(crate) fn answer(&self, refusal: Option<McpRefusal>) {
        *self.answer.lock().unwrap_or_else(PoisonError::into_inner) = refusal;
    }

    /// The candidates applied live so far.
    pub(crate) fn applied(&self) -> Vec<Candidate> {
        self.applied
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The candidates restarted so far.
    pub(crate) fn restarted(&self) -> Vec<Candidate> {
        self.restarted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether each client CA replacement so far was confirmed with the password.
    pub(crate) fn replaced(&self) -> Vec<bool> {
        self.replaced
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Records `candidate` in `log` and answers it.
    fn change(&self, log: &Mutex<Vec<Candidate>>, candidate: Candidate) -> McpChange {
        let refusal = *self.answer.lock().unwrap_or_else(PoisonError::into_inner);
        let result = refusal.map_or_else(
            || {
                commit(&self.store, &candidate).map_err(|error| {
                    if matches!(error, SettingsError::SettingsChanged) {
                        McpRefusal::SettingsChanged
                    } else {
                        McpRefusal::Commit
                    }
                })
            },
            Err,
        );
        log.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(candidate);
        Box::pin(async move { result })
    }
}

impl McpControl for Stub {
    fn apply_live(&self, candidate: Candidate) -> McpChange {
        self.change(&self.applied, candidate)
    }

    fn restart(&self, candidate: Candidate) -> McpChange {
        self.change(&self.restarted, candidate)
    }

    fn replace_client_ca(&self, pem: Vec<u8>, confirmed: bool) -> McpChange {
        self.replaced
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(confirmed);
        let refusal = *self.answer.lock().unwrap_or_else(PoisonError::into_inner);
        let result = refusal.map_or_else(
            || {
                store_mtls_ca(&self.store, &pem)
                    .map(drop)
                    .map_err(|_refused| McpRefusal::Failed)
            },
            Err,
        );
        Box::pin(async move { result })
    }

    fn status(&self) -> McpStatus {
        self.status
    }

    fn toolsets(&self) -> Vec<McpToolset> {
        [("core", false), ("network-write", false), ("raw", true)]
            .into_iter()
            .map(|(name, reduces)| McpToolset::new(name.to_owned(), reduces))
            .collect()
    }
}
