//! `GET /ui/r/{router}/segments` and the segment creation wizard.
//!
//! The page lists the segments kcc created, each with its delete (`segment_delete`). The
//! wizard shows the details, then the review of the router objects it creates, then
//! creates them through the segments domain, which removes the objects already created
//! when a step fails; the list is read back after it.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_app::workflow::WorkflowError;
use kcc_domain::{
    RouterCtx,
    segments::{self, SegmentError},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    Tab, TabLink,
    segment_form::{Details, Problems, SegmentForm},
    segment_known::Known,
    segment_list::Region,
    segment_review::Review,
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        context::{self, Caller},
        failure::plan_failure,
        family::Family,
        gate::Controls,
        outcome::Outcome,
        respond::{self, Answer},
    },
};

/// The segment creation, audited as `web.segments_create`.
pub(super) const CREATE: Operation =
    Operation::write(&segments::DESCRIPTOR, "create", "web.segments_create");

/// The segments page.
#[derive(Template)]
#[template(path = "pages/segments.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The local network tabs.
    tabs: Vec<TabLink>,
    /// Whether the role may create a segment.
    create: bool,
    /// The segments, when the router answered.
    region: Option<Region>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
}

localized!(Page);

/// `GET /ui/r/{router}/segments`: the segments kcc created, with Create segment and each
/// segment's delete when the role may use them.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::Clients, Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let mut page = Page {
        shell,
        tabs: Tab::Segments.links(&router),
        router: router.clone(),
        create: false,
        region: None,
        problem: None,
    };
    let (facts, domain) = match target.context(&state).await {
        Ok(found) => found,
        Err(error) => {
            page.problem = Some(error.message(Family::Changes));
            return errors::render(&page);
        }
    };
    let controls = Controls::new(user.role(), &router)
        .with_operations(segments::DESCRIPTOR.write_ops, Some(facts.catalog()));
    page.create = controls.allows("create");
    match Region::read(&domain, &router, user.locale()).await {
        Ok(region) => page.region = Some(region.deletable(controls.allows("delete"))),
        Err(error) => {
            tracing::warn!(%error, "segments page: the router could not be read");
            page.problem = Some(keys::WEB_SEGMENTS_READ_ERROR);
        }
    }
    errors::render(&page)
}

/// `GET /ui/r/{router}/segments/new`: the details, numbered with the lowest free number.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn details(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let opened = CREATE.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let domain = opened.context().await?;
    let known = known(&domain, locale).await?;
    let form = known
        .free_id()
        .map_or_else(SegmentForm::default, SegmentForm::numbered);
    Ok(errors::render(&Details::new(locale, router, form, known)))
}

/// `POST /ui/r/{router}/segments/new`: Back from the review, with the values as sent.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn back(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let opened = CREATE.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let domain = opened.context().await?;
    let known = known(&domain, locale).await?;
    let form = SegmentForm::from_pairs(&pairs);
    Ok(errors::render(&Details::new(locale, router, form, known)))
}

/// `POST /ui/r/{router}/segments/review`: checks the details and shows what gets created.
///
/// # Errors
///
/// Answers the details with their field errors (422), and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn review(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let opened = CREATE.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let domain = opened.context().await?;
    let known = known(&domain, locale).await?;
    let form = SegmentForm::from_pairs(&pairs);
    let spec = match form.check(&known, locale) {
        Ok(spec) => spec,
        Err(problems) => {
            let details = Details::new(locale, router, form, known);
            return Err(refuse(details, *problems, String::new()));
        }
    };
    if let Err(error) = segments::plan_create(&domain, &spec).await {
        let problem = plan_failure(Family::Changes, locale, &error)
            .message()
            .to_owned();
        let details = Details::new(locale, router, form, known);
        return Err(refuse(details, Problems::default(), problem));
    }
    Ok(errors::render(&Review::new(locale, router, &form, &spec)))
}

/// What the router already has.
///
/// # Errors
///
/// Answers the read's failure, shown in the page's outcome region.
// cancel-safe: reads only.
pub(super) async fn known(domain: &RouterCtx, locale: Locale) -> Result<Known, Answer> {
    Known::read(domain).await.map_err(|error| {
        let failure = plan_failure(Family::Changes, locale, &error);
        let shown = Outcome::failed(failure).render(locale);
        Answer::from(respond::retarget(shown, "#page-outcome"))
    })
}

/// The details again with `problems` and the refusal `problem`, as 422 in the dialog.
pub(super) fn refuse(details: Details, problems: Problems, problem: String) -> Answer {
    let refused = details.refused(problems, problem);
    respond::in_dialog(respond::unprocessable(&refused)).into()
}

/// The sentence naming the failed step, and the workflow error the kit words.
pub(super) fn step_failure(error: SegmentError, locale: Locale) -> (Option<String>, WorkflowError) {
    let mut args = FluentArgs::new();
    let said = match &error {
        SegmentError::StepFailed { step, source: _ } => {
            args.set("name", step.clone());
            Some(tr(locale, keys::WEB_SEGMENTS_FAILED_STEP, Some(&args)))
        }
        SegmentError::RollbackFailed {
            step,
            rollback_step,
            source: _,
        } => {
            args.set("name", step.clone());
            args.set("value", rollback_step.clone());
            Some(tr(locale, keys::WEB_SEGMENTS_ROLLBACK_FAILED, Some(&args)))
        }
        // A planning failure names no step; the domain's enum is not exhaustive here.
        SegmentError::Domain(_) | _ => None,
    };
    (said, WorkflowError::from(error))
}
