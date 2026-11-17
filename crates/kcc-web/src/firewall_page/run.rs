//! How a firewall change runs: the risk it carries, the confirmation it needs, the change
//! and its read-back from a fresh running configuration.
//!
//! A change to a list applied to an interface, or applying a list to one, cuts kcc off
//! when that interface carries kcc's connection to the router. Such a change is a
//! management change: it asks first and runs inside the router's fail-safe timer, with
//! the change's own permission, as on every other page. Every other firewall change is a
//! plain write.

use axum::{http::HeaderMap, response::Response};
use kcc_app::workflow::{CliChangeRequest, WorkflowError};
use kcc_domain::{
    DomainError, RouterCtx,
    firewall::{
        lists::{self, ListEntry},
        management::interfaces_risk,
    },
};
use kcc_i18n::locale::Locale;
use url::form_urlencoded;

use super::{
    expect::Expect,
    rule_actions::Named,
    snapshot,
    views::{Spot, refreshed},
};
use crate::{
    authz::CurrentUser,
    markup::Rendered,
    page_kit::{
        action::Action,
        change::Applied,
        confirm::Resubmit,
        outcome::{Failure, Outcome},
        request::Params,
        respond::Answer,
        submit::{Form, Invalid, Planned as Assessed, Submission},
    },
    routing_page::reply::{Replying, gone, refused, unread},
};

/// A firewall change ready to run: its request, what it must show afterwards and the
/// interfaces whose traffic it changes.
pub(crate) struct Planned {
    /// The CLI request.
    request: CliChangeRequest,
    /// The read-back.
    expect: Expect,
    /// Interfaces whose traffic the change filters differently.
    interfaces: Vec<String>,
}

impl Planned {
    /// `request`, read back as `expect`, changing the traffic of `interfaces`.
    pub(crate) const fn new(
        request: CliChangeRequest,
        expect: Expect,
        interfaces: Vec<String>,
    ) -> Self {
        Self {
            request,
            expect,
            interfaces,
        }
    }
}

/// Who sent the change and from where: the page's headers and the request's pairs, for
/// the region read back and the confirmation sent again.
#[derive(Clone, Copy)]
pub(crate) struct Sender<'request> {
    /// The signed-in user.
    user: &'request CurrentUser,
    /// The page's headers.
    headers: &'request HeaderMap,
    /// Router profile id.
    router: &'request str,
    /// The path the change was posted to.
    path: &'request str,
    /// The request's pairs, query and form.
    pairs: &'request [(String, String)],
}

impl<'request> Sender<'request> {
    /// `user` posting `pairs` to `path` of `router` from the page of `headers`.
    pub(crate) const fn new(
        user: &'request CurrentUser,
        headers: &'request HeaderMap,
        (router, path, pairs): (&'request str, &'request str, &'request [(String, String)]),
    ) -> Self {
        Self {
            user,
            headers,
            router,
            path,
            pairs,
        }
    }

    /// The address that sends the request again once confirmed: the pairs but the
    /// confirmation's own.
    fn resubmit(&self) -> String {
        let mut query = form_urlencoded::Serializer::new(String::new());
        for (name, value) in self.pairs {
            if name != "confirm" && name != "confirm_name" {
                let _: &mut form_urlencoded::Serializer<'_, String> =
                    query.append_pair(name, value);
            }
        }
        format!("{}?{}", self.path, query.finish())
    }

    /// `params` submitted from `form` to `action`, confirmed at the planned risk when it
    /// asks for it, answered as the firewall page answers.
    pub(crate) fn submission<'call, F>(
        &self,
        action: Action<'call>,
        params: &'call Params,
        form: F,
    ) -> Submission<'call, Firewall<F>>
    where
        F: Form,
    {
        let resubmit = Resubmit::new(self.resubmit(), "#page-outcome");
        Submission::new(action, params, Firewall(Replying::new(form)), resubmit)
    }

    /// `planned`, at the risk the firewall domain assesses for the interfaces whose
    /// traffic it changes, run and read back from a fresh running configuration.
    ///
    /// # Errors
    ///
    /// Returns the domain's reason when it could not be planned.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(crate) async fn assess(
        &self,
        domain: &RouterCtx,
        planned: Result<Planned, DomainError>,
    ) -> Result<Assessed, DomainError> {
        let Planned {
            request,
            expect,
            interfaces,
        } = planned?;
        let risk = interfaces_risk(domain, &interfaces).await;
        Ok(Assessed::assessed(risk, move |changes, context| {
            Box::pin(async move {
                let result = changes.apply_cli(request).await?;
                let fresh = snapshot::read(context)
                    .await
                    .map_err(|_message| WorkflowError::InvalidResponse)?;
                if !expect.holds(&fresh) {
                    return Err(WorkflowError::VerificationFailed {
                        field: expect.field(),
                    });
                }
                Ok(Applied::Cli {
                    unsaved: result.unsaved,
                    responses: result.responses,
                })
            })
        }))
    }

    /// The region at `spot` read back for the sender's page, out of band.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(crate) async fn refreshed(
        &self,
        domain: &RouterCtx,
        spot: Spot,
        locale: Locale,
    ) -> Option<Rendered> {
        refreshed(
            domain,
            (self.router, self.user),
            (spot, self.headers),
            locale,
        )
        .await
    }
}

/// A form of the firewall page.
///
/// Values that failed their check are answered by the page's own form, refusals and
/// changes as the routing pages answer them.
pub(crate) struct Firewall<F>(Replying<F>);

impl<F: Form> Form for Firewall<F> {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        self.0.answer_invalid(invalid, locale)
    }

    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        self.0.answer_refused(failure, locale)
    }

    fn answer_changed(
        self,
        outcome: Outcome,
        refreshed: Option<Rendered>,
        locale: Locale,
    ) -> Response {
        self.0.answer_changed(outcome, refreshed, locale)
    }
}

/// The router's firewall and the rule `named`, when it still has it.
///
/// # Errors
///
/// Answers the audited "no longer there" outcome, or why the router could not be read.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn located<'call>(
    action: Action<'call>,
    domain: &RouterCtx,
    named: &Named,
) -> Result<(Action<'call>, lists::Firewall, ListEntry), Answer> {
    match find(domain, named, action.locale()).await {
        Ok((firewall, entry)) => Ok((action, firewall, entry)),
        Err(failure) => Err(refused(action, failure).await.into()),
    }
}

/// The router's firewall and the rule `named`, read with `domain`.
///
/// # Errors
///
/// Returns the failure, in `locale`, of a rule the router no longer has or of a router
/// that could not be read.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn find(
    domain: &RouterCtx,
    named: &Named,
    locale: Locale,
) -> Result<(lists::Firewall, ListEntry), Failure> {
    let firewall = snapshot::read(domain)
        .await
        .map_err(|message| unread(locale, message))?;
    let entry = named.find(&firewall).cloned().ok_or_else(|| gone(locale))?;
    Ok((firewall, entry))
}
