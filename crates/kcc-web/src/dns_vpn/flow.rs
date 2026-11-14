//! The flow the DNS and VPN requests share: the page request, the viewer a region is
//! built for, and how their dialogs answer a submitted change.

use axum::response::{IntoResponse as _, Response};
use kcc_domain::{OperationDescriptor, RouterCtx};
use kcc_i18n::{bundle::tr, locale::Locale};

use super::{
    dns_forms::DnsForm,
    dns_pages::offered,
    screen::{Answered, Tab},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page::Shell,
    page_kit::{
        context::{self, Caller, Refusal},
        failure::plan_failure,
        family::Family,
        form::FormDialog,
        gate::Controls,
        outcome::{Failure, Outcome},
        request::{Params, missing},
        respond,
        submit::{self, Invalid, unplanned::Unplanned},
    },
    table::rows::TableQuery,
};

/// A page request: the services, the signed-in user, the router and the table query.
pub(crate) struct Visit<'call> {
    /// Web services.
    state: &'call WebState,
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
    /// The table's filter, sort and page.
    query: TableQuery,
}

impl<'call> Visit<'call> {
    /// `user` opening a page of `router`.
    pub(crate) fn new(
        state: &'call WebState,
        user: &'call CurrentUser,
        router: &'call str,
    ) -> Self {
        Self {
            state,
            user,
            router,
            query: TableQuery::default(),
        }
    }

    /// The table shows what `query` asks for.
    pub(crate) fn with_table_query(mut self, query: TableQuery) -> Self {
        self.query = query;
        self
    }

    /// Router profile id.
    pub(crate) const fn router(&self) -> &'call str {
        self.router
    }

    /// The user's locale.
    pub(crate) const fn locale(&self) -> Locale {
        self.user.locale()
    }

    /// The full-page shell of `caller` for a page of `tab`, the router selected.
    // cancel-safe: reads only.
    pub(crate) async fn shell(&self, caller: Caller<'_>, tab: Tab) -> Shell {
        caller
            .shell(self.state, tab.section(), Some(self.router))
            .await
    }

    /// Opens the router for a page of `operations`: its domain context and the viewer.
    ///
    /// # Errors
    ///
    /// Returns the refusal of a router the user may not see, or the localized reason the
    /// router cannot be read now.
    // cancel-safe: reads only.
    pub(crate) async fn open(
        self,
        operations: &'static [OperationDescriptor],
    ) -> Result<(RouterCtx, Viewer), Closed> {
        let target = context::target(self.state, self.user, self.router)
            .await
            .map_err(Closed::Refused)?;
        let locale = self.locale();
        match target.context(self.state).await {
            Ok((facts, ctx)) => {
                let controls = Controls::new(self.user.role(), self.router)
                    .with_operations(operations, Some(facts.catalog()));
                let viewer =
                    Viewer::new(self.router, locale, controls).with_table_query(self.query);
                Ok((ctx, viewer))
            }
            Err(error) => Err(Closed::Unreadable(tr(
                locale,
                error.message(Family::Changes),
                None,
            ))),
        }
    }
}

/// Why a page cannot show its router.
pub(crate) enum Closed {
    /// The user may not see the router: 404, 403 or 500.
    Refused(Refusal),
    /// The router cannot be read now; the localized reason.
    Unreadable(String),
}

/// Who views a region: the router, the locale, what the role may change and the table
/// query.
#[derive(Debug, Clone)]
pub(crate) struct Viewer {
    /// Router profile id.
    router: String,
    /// The viewer's locale.
    locale: Locale,
    /// What the role may change on the router.
    controls: Controls,
    /// The table's filter, sort and page.
    query: TableQuery,
}

impl Viewer {
    /// A viewer of `router` in `locale`, who may use `controls`.
    pub(crate) fn new(router: &str, locale: Locale, controls: Controls) -> Self {
        Self {
            router: router.to_owned(),
            locale,
            controls,
            query: TableQuery::default(),
        }
    }

    /// The table shows what `query` asks for.
    pub(crate) fn with_table_query(mut self, query: TableQuery) -> Self {
        self.query = query;
        self
    }

    /// The viewer's locale.
    pub(crate) const fn locale(&self) -> Locale {
        self.locale
    }

    /// Whether the role may run the operation `name`.
    pub(crate) fn allows(&self, name: &str) -> bool {
        self.controls.allows(name)
    }

    /// The table query.
    pub(crate) const fn query(&self) -> &TableQuery {
        &self.query
    }

    /// The page `path` of the router, such as `dns/records`.
    pub(crate) fn href(&self, path: &str) -> String {
        format!("/ui/r/{}/{path}", self.router)
    }
}

/// How the DNS dialog answers a submitted change.
///
/// Values that failed their check come back into the dialog read before the submission,
/// a refused plan into the dialog read again with the plan's context; a dialog whose
/// lists cannot be read answers with that failure in the page's outcome region.
pub(crate) struct Answers<'call> {
    /// The dialog for values that failed their check.
    invalid: Option<FormDialog>,
    /// The submitted dialog, on its router.
    form: (DnsForm, &'call str),
    /// The submitted values.
    values: &'call Params,
}

impl<'call> Answers<'call> {
    /// Values that failed their check answered in `invalid`, a refused plan in the dialog
    /// of `form` on its router, filled with `values`.
    pub(crate) const fn new(
        invalid: Option<FormDialog>,
        form: (DnsForm, &'call str),
        values: &'call Params,
    ) -> Self {
        Self {
            invalid,
            form,
            values,
        }
    }
}

impl submit::Form for Answers<'_> {
    fn answer_invalid(self, invalid: Invalid, _locale: Locale) -> Response {
        self.invalid.map_or_else(
            || missing().into_response(),
            |dialog| dialog.errors(&invalid.into_findings()).invalid(),
        )
    }

    async fn answer_unplanned(self, unplanned: Unplanned<'_>, locale: Locale) -> Response {
        let (form, router) = self.form;
        match offered(form, unplanned.domain()).await {
            Ok(choices) => form
                .dialog(router, locale, &choices)
                .values(self.values)
                .problem(unplanned.into_failure().message().to_owned())
                .invalid(),
            Err(error) => unreadable(plan_failure(Family::Changes, locale, &error), locale),
        }
    }
}

/// How DNS interception answers: a choice it does not offer and a refused plan, both in
/// the page's outcome region.
pub(crate) struct InRegion;

impl submit::Form for InRegion {
    fn answer_invalid(self, invalid: Invalid, locale: Locale) -> Response {
        let problems = invalid
            .into_findings()
            .into_iter()
            .map(|(_field, rule)| tr(locale, rule, None))
            .collect();
        Answered::new(Outcome::invalid(Family::Changes, locale, problems), locale).respond()
    }
}

/// The answer of a dialog whose lists cannot be read: `failure` in the page's outcome
/// region.
pub(crate) fn unreadable(failure: Failure, locale: Locale) -> Response {
    respond::retarget(Outcome::failed(failure).render(locale), "#page-outcome")
}
