//! `POST /ui/r/{router}/segments/create`: the last step of the segment creation wizard.
//!
//! The details are checked again, the segments domain plans the creation and creates the
//! segment step by step, removing what it created when a step fails; the list is read
//! back after it, whether or not the creation went through.

use core::slice;

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::{IntoResponse as _, Response},
};
use kcc_domain::segments;
use kcc_i18n::locale::Locale;

use super::{
    answer,
    segment_form::{Details, Problems, SegmentForm},
    segment_list::Region,
    segments::{CREATE, known, refuse, step_failure},
};
use crate::{
    WebState,
    authz::CurrentUser,
    markup::Rendered,
    page_kit::{
        change::Applied,
        confirm::Resubmit,
        outcome::{Failure, Outcome},
        request::Params,
        respond::Answer,
        submit::{self, Invalid, Planned, Submission, work::Stopped},
    },
    system_pages::shared::merged,
};

/// `POST /ui/r/{router}/segments/create`: checks the details again, creates the segment
/// step by step and answers with its outcome; a failed step names itself.
///
/// # Errors
///
/// Answers the details with their field errors (422), and what the kit answers when the
/// router or the permission is missing.
// NOT cancel-safe: dropped after `submit` sends the change, the router may keep it without its
// read-back, audit entry or timer cleanup.
pub(crate) async fn create(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(body): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), body);
    let action = CREATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let known = known(&action.context().await?, locale).await?;
    let form = SegmentForm::from_pairs(&pairs);
    let checked = form.check(&known, locale);
    let mut creating = Creating {
        details: Details::new(locale, router.clone(), form, known),
        problems: Problems::default(),
    };
    let typed = checked.map_err(|problems| {
        creating.problems = *problems;
        Invalid::from(Vec::new())
    });
    let params = Params::of(pairs);
    let resubmit = Resubmit::new(
        params.again(&format!("/ui/r/{router}/segments/create")),
        "#page-outcome",
    );
    Ok(Submission::new(action, &params, creating, resubmit)
        .refreshing_after_failure()
        .submit(
            |_params| typed,
            async |spec, domain| {
                let operation = segments::plan_create(domain, &spec).await?;
                Ok(Planned::reporting(
                    slice::from_ref(&operation),
                    move |changes, context| {
                        Box::pin(async move {
                            match segments::create(changes, context, &spec).await {
                                Ok(_created) => changes
                                    .current_last_change()
                                    .await
                                    .map(|last| Applied::Done {
                                        unsaved: last.unsaved,
                                    })
                                    .map_err(Stopped::from),
                                Err(error) => Err(step_failure(error, locale)),
                            }
                        })
                    },
                ))
            },
            async |domain| Region::read_back(domain, &router, locale).await,
        )
        .await)
}

/// The details of the segment being created.
struct Creating {
    /// The details, shown again when refused.
    details: Details,
    /// Why each refused field is refused.
    problems: Problems,
}

impl submit::Form for Creating {
    fn answer_invalid(self, _invalid: Invalid, _locale: Locale) -> Response {
        refuse(self.details, self.problems, String::new()).into_response()
    }

    fn answer_refused(self, failure: Failure, _locale: Locale) -> Response {
        refuse(
            self.details,
            Problems::default(),
            failure.message().to_owned(),
        )
        .into_response()
    }

    fn answer_changed(
        self,
        outcome: Outcome,
        refreshed: Option<Rendered>,
        locale: Locale,
    ) -> Response {
        answer(outcome, refreshed, locale)
    }
}
