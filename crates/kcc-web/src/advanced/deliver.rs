//! Sending validated requests and turning the router's answer into an outcome.
//!
//! Reads go through the shared client, changes through the change workflow, and an
//! answer too large for its page is kept for download.

use alloc::sync::Arc;

use fluent_bundle::FluentArgs;
use kcc_app::{
    permissions::Permission,
    workflow::{BatchChangeRequest, BatchItem, CliChangeRequest, CliCommand},
};
use kcc_catalog::{Risk, ValidatedRequest};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::{RciBody, RciClient, RciError, RciResponse};
use serde_json::Value;

use super::{
    outcome::{Left, Reply},
    viewer::Rendered,
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        change::{self, Applied, Change, Landed, Plan},
        context::Target,
        facts::RouterFacts,
        failure::rci_failure,
        family::Family,
        gate::allowed,
        outcome::Failure,
    },
};

/// Who sends a request: the services, the user and the session.
#[derive(Clone, Copy)]
pub(crate) struct Sender<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Opaque session key for kept responses.
    session: &'call str,
}

/// A sender aimed at one router.
#[derive(Clone, Copy)]
pub(crate) struct Dispatch<'call> {
    /// Who sends.
    sender: Sender<'call>,
    /// The router.
    target: Target<'call>,
    /// The router's catalog facts.
    facts: &'call RouterFacts,
    /// Whether the router persists the request at once, when its change cannot say.
    persists: bool,
}

impl<'call> Sender<'call> {
    /// `user` sending in the session `session`.
    pub(crate) const fn new(
        state: &'call WebState,
        user: &'call CurrentUser,
        session: &'call str,
    ) -> Self {
        Self {
            state,
            user,
            session,
        }
    }

    /// Aims at `target` with its `facts`.
    pub(crate) const fn to(
        self,
        target: Target<'call>,
        facts: &'call RouterFacts,
    ) -> Dispatch<'call> {
        Dispatch {
            sender: self,
            target,
            facts,
            persists: false,
        }
    }
}

impl Dispatch<'_> {
    /// The same dispatch for a request the router persists at once when `persists`.
    pub(crate) const fn persisting(mut self, persists: bool) -> Self {
        self.persists = persists;
        self
    }

    /// Runs the read-only root object `root` through the shared client.
    // cancel-safe: a read.
    pub(crate) async fn read_root(self, root: &Value) -> Reply {
        match self.client().await {
            Ok(client) => match client.post_root(root).await {
                Ok(body) => self.answered(&body, Left::Nothing),
                Err(error) => Reply::failed(rci_failure(Family::Commands, self.locale(), &error)),
            },
            Err(failure) => Reply::failed(failure),
        }
    }

    /// Runs read-only root items as one batch through the shared client.
    // cancel-safe: reads.
    pub(crate) async fn read_batch(self, items: Vec<Value>) -> Reply {
        match self.client().await {
            Ok(client) => match client.batch(items).await {
                Ok(responses) => self.items(&responses, Left::Nothing, None),
                Err(error) => Reply::failed(rci_failure(Family::Commands, self.locale(), &error)),
            },
            Err(failure) => Reply::failed(failure),
        }
    }

    /// Runs `request` against the shared client and shows its answer.
    // cancel-safe when `request` only reads.
    pub(crate) async fn read_with<F, Fut>(self, request: F) -> Reply
    where
        F: FnOnce(Arc<RciClient>) -> Fut,
        Fut: Future<Output = Result<RciBody, RciError>>,
    {
        match self.client().await {
            Ok(client) => match request(client).await {
                Ok(body) => self.answered(&body, Left::Nothing),
                Err(error) => Reply::failed(rci_failure(Family::Commands, self.locale(), &error)),
            },
            Err(failure) => Reply::failed(failure),
        }
    }

    /// Applies `change` of `risk` through the change workflow.
    // NOT cancel-safe: see `change::apply`.
    pub(crate) async fn change(self, risk: Risk, change: Change) -> Reply {
        let plan = Plan::new(self.target, self.facts, self.sender.user).at(risk);
        let persists = self.persists
            || match &change {
                Change::Batch(_request, checks) => {
                    checks
                        .iter()
                        .any(|validated| !validated.persisted_paths.is_empty())
                        && checks
                            .iter()
                            .all(|validated| validated.ordinary_paths.is_empty())
                }
                Change::Request(_) | Change::Cli(_) | Change::Delete(_) => change.persists(),
            };
        let persisted_paths = change.persisted_paths(self.facts.catalog());
        let change_items = match &change {
            Change::Batch(_request, checks) => checks
                .iter()
                .map(|validated| {
                    !validated.ordinary_paths.is_empty() || !validated.persisted_paths.is_empty()
                })
                .collect::<Vec<_>>(),
            Change::Request(_) | Change::Cli(_) | Change::Delete(_) => Vec::new(),
        };
        let left = |unsaved| Left::of(unsaved, persists, persisted_paths.clone());
        let locale = self.locale();
        let landed = change::apply(plan, change).await.map(Landed::into_parts);
        let audit_pending = landed.as_ref().is_ok_and(|&(_, pending)| pending);
        let reply = match landed.map(|(applied, _)| applied) {
            Ok(Applied::Batch {
                applied_management_changes: _,
                unsaved,
                persists_immediately,
                persisted_paths: successful_persisted_paths,
                responses,
            }) => self.items(
                &responses,
                Left::of(unsaved, persists_immediately, successful_persisted_paths),
                Some(
                    responses
                        .iter()
                        .zip(&change_items)
                        .filter(|(response, changes)| response.is_ok() && **changes)
                        .count(),
                ),
            ),
            Ok(Applied::Cli { unsaved, responses }) => self.lines(&responses, left(unsaved)),
            Ok(Applied::Terminal(responses)) => self.lines(&responses, Left::Nothing),
            Ok(Applied::Done { unsaved }) => {
                self.shown(Rendered::text("", self.locale()), left(unsaved))
            }
            Err(refused) => Reply::failed(refused.failure(Family::Commands, locale)),
        };
        if audit_pending {
            reply.with_audit_pending(locale)
        } else {
            reply
        }
    }

    /// The outcome of the answers to CLI lines: one shown as it came, several as a list.
    fn lines(self, bodies: &[RciBody], left: Left) -> Reply {
        match bodies {
            [body] => self.answered(body, left),
            many => {
                let values = many.iter().map(body_value).collect();
                let rendered =
                    Rendered::json(&Value::Array(values), &[], self.reveal(), self.locale());
                self.shown(rendered, left)
            }
        }
    }

    /// The outcome of one answer.
    fn answered(self, body: &RciBody, left: Left) -> Reply {
        self.shown(Rendered::body(body, self.reveal(), self.locale()), left)
    }

    /// The outcome of batch answers: every value shown, refused items reported.
    fn items(
        self,
        responses: &[Result<RciResponse, RciError>],
        left: Left,
        applied_changes: Option<usize>,
    ) -> Reply {
        let locale = self.locale();
        let mut values = Vec::with_capacity(responses.len());
        let mut statuses = Vec::new();
        let mut refused = Vec::new();
        for (index, item) in responses.iter().enumerate() {
            match item {
                Ok(response) => {
                    values.push(response.value.clone());
                    statuses.extend(response.statuses.iter().cloned());
                }
                Err(error) => {
                    values.push(Value::Null);
                    let mut args = FluentArgs::new();
                    args.set("index", index.saturating_add(1).to_string());
                    let reason = match error {
                        RciError::Rci {
                            pointer: _,
                            code: _,
                            ident: _,
                            message,
                        } => message.clone(),
                        RciError::Transport
                        | RciError::Timeout
                        | RciError::Http { status: _ }
                        | RciError::Auth(_)
                        | RciError::NotFound
                        | RciError::MethodNotAllowed
                        | RciError::BodyTooLarge
                        | RciError::Decode
                        | RciError::Policy
                        | RciError::Validation
                        | _ => rci_failure(Family::Commands, locale, error)
                            .message()
                            .to_owned(),
                    };
                    args.set("issue", reason);
                    refused.push(tr(locale, keys::WEB_EXPLORER_ISSUE_ITEM, Some(&args)));
                }
            }
        }
        let shown = match values.as_slice() {
            [single] => single.clone(),
            _ => Value::Array(values),
        };
        let rendered = Rendered::json(&shown, &statuses, self.reveal(), locale);
        if refused.is_empty() {
            return self.shown(rendered, left);
        }
        let (viewer, _full, _json) = rendered.into_parts();
        let succeeded =
            applied_changes.unwrap_or_else(|| responses.len().saturating_sub(refused.len()));
        if succeeded != 0 {
            let (headline, audit) = left.partial(locale, succeeded, refused.len());
            return Reply::partial(headline, refused, viewer, &left, audit);
        }
        let answered = refused.len() < responses.len();
        let reply = Reply::failed(
            Failure::new(tr(locale, keys::WEB_EXPLORER_REJECTED, None), "failed")
                .with_router_said(refused),
        );
        // With every item refused the answer holds only their empty places; the router
        // said block already gives each item's refusal.
        if answered {
            reply.with_viewer(viewer)
        } else {
            reply
        }
    }

    /// The outcome showing `rendered`, keeping a truncated answer for download.
    fn shown(self, rendered: Rendered, left: Left) -> Reply {
        let (viewer, full, json) = rendered.into_parts();
        let truncated = viewer.truncated();
        let outcome = Reply::done(self.locale(), viewer, left);
        if !truncated {
            return outcome;
        }
        let router = self.target.router();
        self.sender.state.advanced().keep_response(
            self.sender.session,
            router,
            Arc::from(full),
            json,
        );
        outcome.with_download(format!("/ui/r/{router}/explorer/response"))
    }

    /// The router's shared client.
    ///
    /// # Errors
    ///
    /// Returns the failure to show when the router has no client.
    async fn client(self) -> Result<Arc<RciClient>, Failure> {
        self.target
            .fleet()
            .registry()
            .client(self.target.router())
            .await
            .map_err(|error| {
                tracing::warn!(%error, "advanced request: no router client");
                Failure::new(
                    tr(self.locale(), keys::WEB_EXPLORER_UNREACHABLE, None),
                    "unreachable",
                )
            })
    }

    /// Whether the user may see secrets in answers.
    fn reveal(self) -> bool {
        allowed(
            self.sender.user,
            self.target.router(),
            &[Permission::RevealSecrets],
        )
    }

    /// The user's locale.
    const fn locale(self) -> Locale {
        self.sender.user.locale()
    }
}

/// A raw batch of root items as the explorer and the RCI console send it: `RawRci`, no
/// read-back, audited with the redacted `params`.
pub(crate) fn raw_batch(checked: Vec<(BatchItem, ValidatedRequest)>, params: Value) -> Change {
    let (items, checks) = checked.into_iter().unzip();
    Change::Batch(
        BatchChangeRequest::new(items, Vec::new(), Permission::RawRci, params),
        checks,
    )
}

/// Raw CLI lines as the CLI console sends them: `RawRci`, no read-back, audited with the
/// redacted `params`.
pub(crate) fn raw_cli(commands: Vec<CliCommand>, params: Value) -> Change {
    Change::Cli(CliChangeRequest::new(
        commands,
        Vec::new(),
        Permission::RawRci,
        params,
    ))
}

/// The JSON of one answer; text becomes a string.
fn body_value(body: &RciBody) -> Value {
    match body {
        RciBody::Json(response) => response.value.clone(),
        RciBody::Text(text) => Value::String(text.clone()),
        _ => Value::Null,
    }
}
