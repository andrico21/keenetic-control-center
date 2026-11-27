//! Log lines of failed requests and sign-ins, with identical warnings collapsed per client.

use alloc::borrow::Cow;
use core::{fmt, time::Duration};
use std::{sync::Mutex, time::Instant};

use reqwest::Method;
use tracing::field;

use super::{
    lock,
    send::{RequestLabel, millis},
};
use crate::{Admit, AuthError, DecodeDetail, DedupeKey, Deduper, RciError, observe::LoginScheme};

/// The log identity of one client and its collapsed warnings.
#[derive(Debug, Default)]
pub(crate) struct Journal {
    /// The router profile id every line carries; empty when unset.
    id: String,
    /// Warnings already logged, so identical ones within a minute collapse.
    collapse: Mutex<Deduper>,
}

/// Why a request failed, in kcc's own words: never the router's message or a value.
#[derive(Clone, Debug)]
pub(crate) struct Cause<'error> {
    /// Stable snake-case class, such as `connect_refused` or `http_500`.
    class: Cow<'static, str>,
    /// The router error's subsystem.
    ident: Option<&'error str>,
    /// The router error's code.
    code: Option<&'error str>,
    /// Where an answer could not be read.
    detail: Option<&'error DecodeDetail>,
}

impl<'error> Cause<'error> {
    /// The cause of `error`.
    pub(crate) fn of(error: &'error RciError) -> Self {
        let class = |class: &'static str| Self {
            class: Cow::Borrowed(class),
            ident: None,
            code: None,
            detail: None,
        };
        match error {
            RciError::Transport(cause) => class(cause.label()),
            RciError::Timeout => class("timeout"),
            RciError::Cancelled => class("cancelled"),
            RciError::Http { status } => Self {
                class: Cow::Owned(format!("http_{status}")),
                ..class("")
            },
            RciError::Auth(auth) => class(match auth {
                AuthError::Rejected => "auth_rejected",
                AuthError::Unsupported => "auth_unsupported",
                AuthError::CostTooHigh => "auth_cost_too_high",
                AuthError::ServerSignatureMismatch => "auth_server_signature_mismatch",
                AuthError::TokenRejected => "auth_token_rejected",
            }),
            RciError::Rci {
                pointer: _,
                code,
                ident,
                message: _,
            } => Self {
                ident: Some(ident),
                code: Some(code),
                ..class("router_error")
            },
            RciError::NotFound => class("not_found"),
            RciError::MethodNotAllowed => class("method_not_allowed"),
            RciError::BodyTooLarge => class("body_too_large"),
            RciError::Decode(detail) => Self {
                detail: Some(detail),
                ..class("decode")
            },
            RciError::Policy => class("policy"),
            RciError::Validation => class("validation"),
        }
    }

    /// The cause as one dedupe key part: identical warnings share it.
    fn key(&self) -> String {
        let mut key = self.class.clone().into_owned();
        for part in [self.ident, self.code].into_iter().flatten() {
            key.push(' ');
            key.push_str(part);
        }
        if let Some(detail) = self.detail {
            key.push(' ');
            key.push_str(&detail.to_string());
        }
        key
    }
}

impl fmt::Display for Cause<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.class)
    }
}

/// The variant name of a sign-in refusal.
const fn auth_name(error: AuthError) -> &'static str {
    match error {
        AuthError::Rejected => "Rejected",
        AuthError::Unsupported => "Unsupported",
        AuthError::CostTooHigh => "CostTooHigh",
        AuthError::ServerSignatureMismatch => "ServerSignatureMismatch",
        AuthError::TokenRejected => "TokenRejected",
    }
}

impl Journal {
    /// A journal whose lines carry the router profile id `id`.
    pub(crate) fn new(id: String) -> Self {
        Self {
            id,
            collapse: Mutex::new(Deduper::default()),
        }
    }

    /// The router profile id this journal's lines carry.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// The label of a request of this client to `target`.
    pub(crate) fn label(&self, method: &Method, target: &str) -> RequestLabel<'_> {
        RequestLabel::new(&self.id, method, target)
    }

    /// Logs a request that returns `error` to its caller after `elapsed`: a missing
    /// resource, a refused method and a cancellation at DEBUG, everything else once per
    /// minute at WARN.
    pub(crate) fn failed(&self, label: &RequestLabel<'_>, elapsed: Duration, error: &RciError) {
        self.failed_at(label, elapsed, error, Instant::now());
    }

    /// [`Self::failed`] at the instant `now`.
    fn failed_at(
        &self,
        label: &RequestLabel<'_>,
        elapsed: Duration,
        error: &RciError,
        now: Instant,
    ) {
        let cause = Cause::of(error);
        let ms = millis(elapsed);
        if matches!(
            error,
            RciError::NotFound | RciError::MethodNotAllowed | RciError::Cancelled
        ) {
            tracing::debug!(
                router = %label.router,
                method = %label.method,
                path = %label.path,
                query = label.query.then_some(true),
                ms,
                cause = %cause,
                "router request failed"
            );
            return;
        }
        let key = (
            self.id.clone(),
            label.method.to_string(),
            label.path.clone(),
            cause.key(),
        );
        let Admit::Log { suppressed } = self.admit(key, now) else {
            return;
        };
        tracing::warn!(
            router = %label.router,
            method = %label.method,
            path = %label.path,
            query = label.query.then_some(true),
            ms,
            cause = %cause,
            ident = cause.ident.map(field::debug),
            code = cause.code.map(field::debug),
            detail = cause.detail.map(field::display),
            suppressed = (suppressed > 0).then_some(suppressed),
            "router request failed"
        );
    }

    /// Logs the outcome of one sign-in that took `elapsed`: success at DEBUG, a refusal
    /// once per minute at WARN, any other failure at DEBUG (the request's own line names it).
    pub(crate) fn signed_in(&self, result: &Result<LoginScheme, RciError>, elapsed: Duration) {
        let ms = millis(elapsed);
        match result {
            Ok(scheme) => tracing::debug!(
                router = %self.id,
                scheme = %scheme.as_str(),
                ms,
                "signed in"
            ),
            Err(RciError::Auth(error)) => {
                let name = auth_name(*error);
                let key = (
                    self.id.clone(),
                    Method::POST.to_string(),
                    "/auth".to_owned(),
                    name.to_owned(),
                );
                if let Admit::Log { suppressed } = self.admit(key, Instant::now()) {
                    tracing::warn!(
                        router = %self.id,
                        error = %name,
                        ms,
                        suppressed = (suppressed > 0).then_some(suppressed),
                        "sign-in failed"
                    );
                }
            }
            Err(other) => tracing::debug!(
                router = %self.id,
                cause = %Cause::of(other),
                ms,
                "sign-in failed"
            ),
        }
    }

    /// Whether the warning `key` at `now` is logged; the lock is held for this call only.
    fn admit(&self, key: DedupeKey, now: Instant) -> Admit {
        lock(&self.collapse).admit(key, now)
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
