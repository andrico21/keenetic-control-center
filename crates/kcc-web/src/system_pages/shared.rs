//! What the system pages share: opening a page on its router, the query strings their
//! actions carry, and how a change without a dialog answers.

use axum::{
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{
    DomainError, Result as DomainResult, RouterCtx, router_users::protection::OwnLogins,
};
use kcc_i18n::{bundle::MessageKey, locale::Locale};
use url::form_urlencoded;

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    errors::Kind,
    nav::Section,
    net_change::unusable,
    page::Shell,
    page_kit::{
        action::Action,
        context,
        context::{Caller, fragment_shell},
        facts::RouterFacts,
        family::Family,
        outcome::{Failure, Outcome},
        request::{last, missing},
        respond::{Answer, changed},
        submit::{self, Invalid},
    },
};

/// The router a system page reads: its catalog facts and the domain context, or why the
/// router cannot be read now.
pub(crate) type Reading = Result<(RouterFacts, RouterCtx), MessageKey>;

/// Who opens a page: the request headers, the session and the signed-in user.
#[derive(Clone, Copy)]
pub(crate) struct Visit<'request> {
    /// Request headers, for the theme cookie.
    headers: &'request HeaderMap,
    /// Session, for the CSRF token.
    current: &'request CurrentSession,
    /// Signed-in user.
    user: &'request CurrentUser,
}

impl<'request> Visit<'request> {
    /// The visit of one request.
    pub(crate) const fn new(
        headers: &'request HeaderMap,
        current: &'request CurrentSession,
        user: &'request CurrentUser,
    ) -> Self {
        Self {
            headers,
            current,
            user,
        }
    }

    /// Opens a system page on `router`: the full shell with the router selected and the
    /// System section current, then the router's facts and domain context.
    ///
    /// # Errors
    ///
    /// The error page when the router is unknown, outside the role's scope or the fleet
    /// is not configured.
    // NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned
    // router session. Apart from that, reads only.
    pub(crate) async fn open(
        self,
        state: &WebState,
        router: &str,
    ) -> Result<(Shell, Reading), Answer> {
        let shell = Caller::new(self.headers, self.current, self.user)
            .shell(state, Section::System, Some(router))
            .await;
        let target = match context::target(state, self.user, router).await {
            Ok(found) => found,
            Err(refusal) => return Err(refusal.page(shell).into()),
        };
        let reading = target
            .context(state)
            .await
            .map_err(|error| error.message(Family::Changes));
        Ok((shell, reading))
    }
}

/// The pairs of a request's query string, then those of its form body.
pub(crate) fn merged(query: Option<&str>, form: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = query.map_or_default(|text| {
        form_urlencoded::parse(text.as_bytes())
            .into_owned()
            .collect()
    });
    pairs.extend(form);
    pairs
}

/// The last value of `name` in `pairs`, trimmed.
pub(crate) fn value<'pairs>(pairs: &'pairs [(String, String)], name: &str) -> Option<&'pairs str> {
    last(pairs, name).map(str::trim)
}

/// Every value of `name` in `pairs`, trimmed, in order.
pub(crate) fn values<'pairs>(pairs: &'pairs [(String, String)], name: &str) -> Vec<&'pairs str> {
    pairs
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, found)| found.trim())
        .collect()
}

/// The 403 answer of an action the role may not take at the risk it would run at.
pub(crate) fn forbidden(locale: Locale) -> Answer {
    errors::response(Kind::Forbidden, fragment_shell(locale)).into()
}

/// A change without a dialog of its own: values that fail their check name nothing the
/// page has (404), and a change the domain could not plan is shown refused in the page's
/// outcome region.
pub(crate) struct NoDialog;

impl submit::Form for NoDialog {
    fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
        missing().into_response()
    }

    fn answer_refused(self, failure: Failure, locale: Locale) -> Response {
        refused(&failure, locale)
    }
}

/// A change the domain could not plan, shown refused in the page's outcome region:
/// nothing was sent.
pub(crate) fn refused(failure: &Failure, locale: Locale) -> Response {
    let problems = vec![failure.message().to_owned()];
    changed(
        Outcome::invalid(Family::Changes, locale, problems),
        None,
        None,
        locale,
    )
}

/// The router accounts kcc signs in to `router` with, which account changes must keep.
///
/// # Errors
///
/// [`DomainError::ProtectedAccount`] when the profile cannot be read, is not visible to
/// `user` or names no login: kcc cannot tell its own account then, so every account is
/// protected.
// cancel-safe: reads only.
pub(crate) async fn profile_login(
    state: &WebState,
    user: &CurrentUser,
    router: &str,
) -> DomainResult<OwnLogins> {
    let fleet = state.fleet().ok_or(DomainError::ProtectedAccount)?;
    match context::lookup(fleet, user.role(), router).await {
        Ok(Some(entry)) => {
            OwnLogins::new(&entry.profile.login, entry.profile.read_login.as_deref())
        }
        Ok(None) => Err(DomainError::ProtectedAccount),
        Err(error) => {
            tracing::warn!(%error, "router profile could not be read");
            Err(DomainError::ProtectedAccount)
        }
    }
}

/// Ends `action` because the router could not be read to check what the change names:
/// the change is not taken as one on an absent object, it answers unreachable.
// NOT cancel-safe: an abandoned append may still be written.
pub(crate) async fn unread(action: Action<'_>) -> Answer {
    let locale = action.locale();
    action.abandon("unreachable").await;
    unusable(locale, Family::Changes.unreachable())
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{merged, value, values};
    use crate::page_kit::request::with_query;

    #[test]
    fn action_queries_round_trip_through_the_resubmitted_url() {
        let url = with_query(
            "/ui/r/home/system/users",
            &[("name", "a b"), ("tag", "cli")],
        );
        assert_eq!(url, "/ui/r/home/system/users?name=a+b&tag=cli", "encoded");
        let query = url.split_once('?').map(|(_, query)| query);
        let pairs = merged(query, vec![("tag".to_owned(), " http ".to_owned())]);
        assert_eq!(value(&pairs, "name"), Some("a b"), "decoded");
        assert_eq!(
            values(&pairs, "tag"),
            ["cli", "http"],
            "query then form, trimmed"
        );
        assert_eq!(value(&pairs, "missing"), None, "absent");
    }
}
