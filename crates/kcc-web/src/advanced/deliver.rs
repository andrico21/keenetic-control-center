//! Sending validated requests and turning the router's answer into an outcome.
//!
//! Reads go through the shared client, changes through the change workflow, and an
//! answer too large for its page is kept for download.

use alloc::sync::Arc;

use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_catalog::Risk;
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use kcc_rci::{RciBody, RciClient, RciError, RciResponse};
use serde_json::Value;

use super::{
    apply::{self, Applied, Change, Plan, Refused},
    context::{Target, allowed},
    facts::RouterFacts,
    gate::FAIL_SAFE_MINUTES,
    outcome::{Failure, Outcome, rci_failure, workflow_failure},
    viewer::Rendered,
};
use crate::{WebState, authz::CurrentUser};

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
        }
    }
}

impl Dispatch<'_> {
    /// Runs the read-only root object `root` through the shared client.
    // cancel-safe: a read.
    pub(crate) async fn read_root(self, root: &Value) -> Outcome {
        match self.client().await {
            Ok(client) => match client.post_root(root).await {
                Ok(body) => self.answered(&body, false),
                Err(error) => Outcome::failed(rci_failure(self.locale(), &error)),
            },
            Err(failure) => Outcome::failed(failure),
        }
    }

    /// Runs read-only root items as one batch through the shared client.
    // cancel-safe: reads.
    pub(crate) async fn read_batch(self, items: Vec<Value>) -> Outcome {
        match self.client().await {
            Ok(client) => match client.batch(items).await {
                Ok(responses) => self.items(&responses, false),
                Err(error) => Outcome::failed(rci_failure(self.locale(), &error)),
            },
            Err(failure) => Outcome::failed(failure),
        }
    }

    /// Runs `request` against the shared client and shows its answer.
    // cancel-safe when `request` only reads.
    pub(crate) async fn read_with<F, Fut>(self, request: F) -> Outcome
    where
        F: FnOnce(Arc<RciClient>) -> Fut,
        Fut: Future<Output = Result<RciBody, RciError>>,
    {
        match self.client().await {
            Ok(client) => match request(client).await {
                Ok(body) => self.answered(&body, false),
                Err(error) => Outcome::failed(rci_failure(self.locale(), &error)),
            },
            Err(failure) => Outcome::failed(failure),
        }
    }

    /// Applies `change` of `risk` through the change workflow, audited with `params`.
    // NOT cancel-safe: see `apply::apply`.
    pub(crate) async fn change(self, risk: Risk, params: Value, change: Change) -> Outcome {
        let plan = Plan::new(self.target, self.facts, self.sender.user).with(risk, params);
        match apply::apply(plan, change).await {
            Ok(Applied::Batch(responses)) => self.items(&responses, true),
            Ok(Applied::Cli(bodies)) => match bodies.as_slice() {
                [body] => self.answered(body, true),
                many => {
                    let values = many.iter().map(body_value).collect();
                    let rendered =
                        Rendered::json(&Value::Array(values), &[], self.reveal(), self.locale());
                    self.shown(rendered, true)
                }
            },
            Ok(Applied::Delete) => self.shown(Rendered::text("", self.locale()), true),
            Err(refused) => Outcome::failed(self.refusal(&refused)),
        }
    }

    /// The outcome of one answer.
    fn answered(self, body: &RciBody, unsaved: bool) -> Outcome {
        self.shown(Rendered::body(body, self.reveal(), self.locale()), unsaved)
    }

    /// The outcome of batch answers: every value shown, refused items reported.
    fn items(self, responses: &[Result<RciResponse, RciError>], unsaved: bool) -> Outcome {
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
                        | _ => rci_failure(locale, error).message().to_owned(),
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
            return self.shown(rendered, unsaved);
        }
        let (viewer, _full, _json) = rendered.into_parts();
        Outcome::failed(
            Failure::new(tr(locale, keys::WEB_EXPLORER_REJECTED, None), "rci_error")
                .with_router_said(refused),
        )
        .with_viewer(viewer)
    }

    /// The outcome showing `rendered`, keeping a truncated answer for download.
    fn shown(self, rendered: Rendered, unsaved: bool) -> Outcome {
        let (viewer, full, json) = rendered.into_parts();
        let truncated = viewer.truncated();
        let outcome = Outcome::done(self.locale(), viewer, unsaved);
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

    /// The failure of a refused change.
    fn refusal(self, refused: &Refused) -> Failure {
        if refused.armed() {
            let mut args = FluentArgs::new();
            args.set("minutes", FAIL_SAFE_MINUTES.to_string());
            return Failure::new(
                tr(self.locale(), keys::WEB_EXPLORER_ARMED, Some(&args)),
                "fail_safe_armed",
            );
        }
        workflow_failure(self.locale(), refused.error())
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

/// The JSON of one answer; text becomes a string.
fn body_value(body: &RciBody) -> Value {
    match body {
        RciBody::Json(response) => response.value.clone(),
        RciBody::Text(text) => Value::String(text.clone()),
        _ => Value::Null,
    }
}
