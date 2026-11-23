//! The desk every SSH action of the Entware page goes through.
//!
//! It checks the router and `Destructive` before anything else, asks for the router name,
//! bounds reads and answers in the page's outcome region.

use alloc::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_app::{
    audit::{Actor, ActorKind},
    permissions::Permission,
};
use kcc_domain::{
    RouterCtx,
    entware::ssh::{Caller, SshServices, error::EntwareError},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use tokio::time::timeout;

use super::{entware::Viewer, entware_ssh_errors::answer_to};
use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    markup::Rendered,
    page_kit::{
        audit::Record,
        confirm::{Ask, Confirmation, Dialog, Gate, Guard, Resubmit, Typed, Words},
        context::{self, Target, fragment_shell},
        family::Family,
        gate::allowed,
        outcome::{Failure, Outcome},
        respond::{Answer, changed, retarget},
    },
};

/// What an action does, as its confirmation says.
#[derive(Clone, Copy)]
pub(super) enum Doing {
    /// Signs in with kcc's key to read.
    Read,
    /// Reads the host key without signing in.
    Probe,
    /// Changes only kcc's own record.
    Local,
    /// Changes the router over SSH.
    Change,
}

impl Doing {
    /// The confirmation's explanation.
    const fn text(self) -> MessageKey {
        match self {
            Self::Read => keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_READ,
            Self::Probe => keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_PROBE,
            Self::Local => keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_LOCAL,
            Self::Change => keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_CHANGE,
        }
    }
}

/// One SSH action of one user on one router, opened after its checks.
pub(super) struct Desk<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// The router and its fleet services.
    target: Target<'call>,
    /// The page's own audit record of the action, for what the page refuses.
    record: Record,
    /// The audited principal.
    actor: Actor,
    /// The SSH services.
    services: Arc<SshServices>,
}

impl<'call> Desk<'call> {
    /// Opens the action `action` (its audit id) on `router` for `user`.
    ///
    /// # Errors
    ///
    /// 503 while the audit log cannot write or without the fleet, 404 for a router the
    /// user cannot see, and the audited 403 without `Destructive` on the router: all
    /// before anything reaches the router.
    // NOT cancel-safe: a refusal queues an audit entry that may be written after the future is
    // dropped.
    pub(super) async fn open(
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
        action: &'static str,
    ) -> Result<Self, Answer> {
        if state.audit().require_alive().is_err() {
            return Err(StatusCode::SERVICE_UNAVAILABLE.into_response().into());
        }
        let target = context::target(state, user, router)
            .await
            .map_err(context::Refusal::status)?;
        let record = Record::on_router(action, router, "entware ssh".to_owned());
        if !allowed(user, router, &[Permission::Destructive]) {
            record.append(state, user, "forbidden").await;
            let shell = fragment_shell(user.locale());
            return Err(errors::response(Kind::Forbidden, shell).into());
        }
        let Some(services) = state.entware_ssh().services(state) else {
            return Err(StatusCode::SERVICE_UNAVAILABLE.into_response().into());
        };
        Ok(Self {
            state,
            user,
            target,
            record,
            actor: Actor::new(ActorKind::Web, user.username().to_owned()),
            services,
        })
    }

    /// The user's locale.
    pub(super) const fn locale(&self) -> Locale {
        self.user.locale()
    }

    /// Web services.
    pub(super) const fn state(&self) -> &'call WebState {
        self.state
    }

    /// The signed-in user.
    pub(super) const fn user(&self) -> &'call CurrentUser {
        self.user
    }

    /// Router profile id.
    pub(super) const fn router(&self) -> &'call str {
        self.target.router()
    }

    /// The audited principal.
    pub(super) const fn actor(&self) -> &Actor {
        &self.actor
    }

    /// The SSH services.
    pub(super) const fn services(&self) -> &Arc<SshServices> {
        &self.services
    }

    /// Who runs the action, as the SSH flows take it.
    pub(super) const fn caller(&self) -> Caller<'_> {
        Caller::new(self.router(), &self.actor, self.user.role())
    }

    /// The kit's dialog asking for the router name, saying what the action `doing` does,
    /// until `pairs` carry the name; confirming sends the request again by `resubmit`.
    pub(super) fn ask(
        &self,
        pairs: &[(String, String)],
        resubmit: Resubmit,
        doing: Doing,
    ) -> Option<Response> {
        let confirmation = Confirmation::from_pairs(pairs);
        let Gate::Ask { wrong_name } = Guard::Destructive.check(&confirmation, self.router())
        else {
            return None;
        };
        let locale = self.locale();
        let mut args = FluentArgs::new();
        args.set("router", self.router().to_owned());
        args.set("name", self.router().to_owned());
        let error = if wrong_name {
            tr(locale, keys::WEB_EXPLORER_CONFIRM_NAME_ERROR, Some(&args))
        } else {
            String::new()
        };
        let words = Words::new(
            tr(
                locale,
                keys::WEB_SYSTEM_ENTWARE_SSH_CONFIRM_TITLE,
                Some(&args),
            ),
            tr(locale, doing.text(), None),
            tr(locale, keys::WEB_KIT_CONFIRM, None),
        );
        let typed = Typed::router(locale).with_error(error);
        Some(
            Dialog::new(locale, words, resubmit)
                .with_text_key(doing.text())
                .asking(Ask::Typed(typed))
                .show(),
        )
    }

    /// The domain context: the router's client and catalog.
    ///
    /// # Errors
    ///
    /// The audited answer when the router cannot be read now.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session.
    pub(super) async fn context(&self) -> Result<RouterCtx, Answer> {
        match self.target.context(self.state).await {
            Ok((_facts, domain)) => Ok(domain),
            Err(error) => {
                let message = tr(self.locale(), error.message(Family::Changes), None);
                Err(self
                    .refuse(Failure::new(message, "unreachable"))
                    .await
                    .into())
            }
        }
    }

    /// The Entware region read again, out of band.
    // NOT cancel-safe: it may sign in first.
    pub(super) async fn refreshed(&self) -> Option<Rendered> {
        let (_facts, domain) = self.target.context(self.state).await.ok()?;
        Viewer::new(self.state, self.user, self.router())
            .refreshed(&domain)
            .await
    }

    /// Answers the page's own refusal `failure` in the outcome region and audits it.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(super) async fn refuse(&self, failure: Failure) -> Response {
        self.record
            .clone()
            .append(self.state, self.user, failure.audit())
            .await;
        self.answer(Outcome::failed(failure), None, None)
    }

    /// Answers `error` of an SSH flow, which audited it; `refreshed` goes out of band.
    pub(super) fn failed(&self, error: &EntwareError, refreshed: Option<Rendered>) -> Response {
        let (failure, extra) = answer_to(error, self.locale());
        self.answer(Outcome::failed(failure), extra, refreshed)
    }

    /// Answers `error` of a step the flows do not audit, and audits it.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(super) async fn failed_unaudited(
        &self,
        error: &EntwareError,
        refreshed: Option<Rendered>,
    ) -> Response {
        let (failure, extra) = answer_to(error, self.locale());
        self.record
            .clone()
            .append(self.state, self.user, failure.audit())
            .await;
        self.answer(Outcome::failed(failure), extra, refreshed)
    }

    /// Audits `outcome` as the page's record and answers it with `refreshed`.
    // NOT cancel-safe: an abandoned append may still be written.
    pub(super) async fn recorded(&self, outcome: Outcome, refreshed: Option<Rendered>) -> Response {
        self.record
            .clone()
            .append(self.state, self.user, outcome.audit())
            .await;
        self.answer(outcome, None, refreshed)
    }

    /// `outcome` in the page's outcome region with `extra` after it and `refreshed` out
    /// of band, the dialog closed.
    pub(super) fn answer(
        &self,
        outcome: Outcome,
        extra: Option<Rendered>,
        refreshed: Option<Rendered>,
    ) -> Response {
        retarget(
            changed(outcome, refreshed, extra, self.locale()),
            "#page-outcome",
        )
    }

    /// The audit record of the page, to record a started job.
    pub(super) fn record(&self) -> Record {
        self.record.clone()
    }

    /// Runs `read` for at most the page's read bound.
    ///
    /// # Errors
    ///
    /// The answer to the flow's error, or the audited answer that the router is busy or
    /// slow when the bound passed (the read is dropped then).
    // NOT cancel-safe: dropping `read` may leave its audit entry unwritten.
    pub(super) async fn read<T, F>(&self, read: F) -> Result<T, Answer>
    where
        F: Future<Output = Result<T, EntwareError>>,
    {
        match timeout(self.state.entware_ssh().read_limit(), read).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(self.failed(&error, None).into()),
            Err(_elapsed) => {
                let message = tr(self.locale(), keys::WEB_SYSTEM_ENTWARE_SSH_SLOW, None);
                Err(self.refuse(Failure::new(message, "timeout")).await.into())
            }
        }
    }
}
