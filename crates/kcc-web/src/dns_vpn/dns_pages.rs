//! The DNS pages at `/ui/r/{router}/dns`: the tabs, their dialogs and their changes.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::{
    DomainError, RouterCtx,
    dns::{self, DnsChange},
    interfaces,
};
use kcc_i18n::{bundle::tr, keys};

use super::{
    cells::Act,
    dns_forms::{Choices, DnsForm},
    dns_read::{DnsState, Entry},
    dns_tabs,
    flow::{self, Closed, Viewer, Visit},
    form::{FormDialog, Values},
    region::Region,
    screen::{Answered, Page, Tab, missing},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    page_kit::{
        action::{Action, Operation},
        context::Caller,
        failure::plan_failure,
        family::Family,
        gate::Controls,
        outcome::Outcome,
        respond::{self, Answer},
    },
    table::rows::TableQuery,
};

/// Interception on or off, audited as `web.dns_intercept`.
const INTERCEPT: Operation = Operation::write(&dns::DESCRIPTOR, "intercept", "web.dns_intercept");

/// `GET /ui/r/{router}/dns`: the servers tab.
pub(crate) async fn servers(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let caller = Caller::new(&headers, &current, &user);
    show(
        Visit::new(&state, &user, &router).with_query(query),
        caller,
        Tab::Servers,
    )
    .await
}

/// `GET /ui/r/{router}/dns/{tab}`: the filtering, records, lists or routes tab.
pub(crate) async fn tab(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let caller = Caller::new(&headers, &current, &user);
    let visit = Visit::new(&state, &user, &router).with_query(query);
    match Tab::dns(&slug) {
        Some(found) => show(visit, caller, found).await,
        None => errors::response(Kind::NotFound, visit.shell(caller, Tab::Servers).await),
    }
}

/// The page of the DNS `tab`.
// cancel-safe: reads only.
async fn show(visit: Visit<'_>, caller: Caller<'_>, tab: Tab) -> Response {
    let shell = visit.shell(caller, tab).await;
    let locale = visit.locale();
    let router = visit.router().to_owned();
    let (region, actions) = match visit.open(dns::DESCRIPTOR.write_ops).await {
        Ok((ctx, viewer)) => region(&ctx, tab, &viewer).await,
        Err(Closed::Refused(refusal)) => return refusal.page(shell),
        Err(Closed::Unreadable(reason)) => (Region::failed(locale, reason), Vec::new()),
    };
    errors::render(&Page::new(shell, (router, tab), region).with_actions(actions))
}

/// The region of `tab` and its page actions, read from the router of `ctx`.
// cancel-safe: reads only.
async fn region(ctx: &RouterCtx, tab: Tab, viewer: &Viewer) -> (Region, Vec<Act>) {
    match DnsState::read(ctx).await {
        Ok(state) => dns_tabs::tab(&state, tab, viewer),
        Err(error) => {
            let locale = viewer.locale();
            let failure = plan_failure(Family::Changes, locale, &error);
            (
                Region::failed(locale, failure.message().to_owned()),
                Vec::new(),
            )
        }
    }
}

/// `GET /ui/r/{router}/dns/form/{form}`: a DNS dialog; the query fills its fields.
///
/// # Errors
///
/// Answers 404 for a dialog the page does not have, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn dialog(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    Query(prefill): Query<Vec<(String, String)>>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let form = DnsForm::from_slug(&slug).ok_or_else(missing)?;
    let values = Values::new(prefill);
    let action = form.operation(&values).open(&state, &user, &router).await?;
    Ok(again(form, &action, &values).await?.show())
}

/// `POST /ui/r/{router}/dns/form/{form}`: checks the values, plans the change with the DNS
/// domain, runs it and answers with its outcome and the tab read back.
///
/// # Errors
///
/// Answers the dialog with its errors (422) when a value is invalid, and what the kit
/// answers when the router or the permission is missing.
pub(crate) async fn submit(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let form = DnsForm::from_slug(&slug).ok_or_else(missing)?;
    let values = Values::new(pairs);
    let action = form.operation(&values).open(&state, &user, &router).await?;
    let locale = action.locale();
    let planned = match form.check(&values) {
        Ok(planned) => planned,
        Err(problems) => {
            let shown = again(form, &action, &values).await?;
            action.abandon("validation_failed").await;
            return Err(shown.errors(&problems).invalid().into());
        }
    };
    let ctx = action.context().await?;
    let request = match planned
        .plan(&ctx)
        .and_then(|operation| dns::change_request(&operation))
    {
        Ok(request) => request,
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            let shown = again(form, &action, &values).await?;
            action.abandon("validation_failed").await;
            return Err(shown.problem(failure.message().to_owned()).invalid().into());
        }
    };
    let viewer = Viewer::new(&router, locale, controls(&ctx, &user, &router))
        .with_query(flow::shown_query(&headers));
    let answered = flow::apply(action, request, Risk::Write, async || {
        region(&ctx, form.tab(), &viewer).await
    });
    Ok(answered.await.respond())
}

/// `POST /ui/r/{router}/dns/intercept`: turns DNS interception on (`enabled=on`) or off.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn intercept(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let values = Values::new(pairs);
    let action = INTERCEPT.open(&state, &user, &router).await?;
    let locale = action.locale();
    let enabled = match values.get("enabled") {
        "on" => true,
        "off" => false,
        _ => {
            action.abandon("validation_failed").await;
            let problem = tr(locale, keys::WEB_DNS_ERROR_CHOICE, None);
            let outcome = Outcome::invalid(Family::Changes, locale, vec![problem]);
            return Ok(Answered::new(outcome, locale).respond());
        }
    };
    let ctx = action.context().await?;
    let planned = dns::plan_change(&ctx, &DnsChange::Intercept { enabled });
    let request = match planned.and_then(|operation| dns::change_request(&operation)) {
        Ok(request) => request,
        Err(error) => {
            let failure = plan_failure(Family::Changes, locale, &error);
            action.abandon(failure.audit()).await;
            return Ok(Answered::new(Outcome::failed(failure), locale).respond());
        }
    };
    let viewer = Viewer::new(&router, locale, controls(&ctx, &user, &router))
        .with_query(flow::shown_query(&headers));
    let answered = flow::apply(action, request, Risk::Write, async || {
        region(&ctx, Tab::Filtering, &viewer).await
    });
    Ok(answered.await.respond())
}

/// What the role may change on `router` through the DNS domain, as `ctx`'s catalog has it.
fn controls(ctx: &RouterCtx, user: &CurrentUser, router: &str) -> Controls {
    Controls::new(user.role(), router)
        .with_operations(dns::DESCRIPTOR.write_ops, Some(&ctx.catalog))
}

/// The dialog of `form` for `action`, filled with `values`; the lists, profiles and
/// interfaces it offers are read from the router.
///
/// # Errors
///
/// Answers the failure, in the page's outcome region, when the router cannot be read.
// cancel-safe: reads only.
async fn again(form: DnsForm, action: &Action<'_>, values: &Values) -> Result<FormDialog, Answer> {
    let locale = action.locale();
    let choices = if form.reads_choices() {
        let ctx = action.context().await?;
        let read = async {
            let state = DnsState::read(&ctx).await?;
            let names = |entries: Vec<Entry>| {
                entries
                    .iter()
                    .map(|entry| entry.name().to_owned())
                    .collect()
            };
            let found = interfaces::read_interfaces(&ctx).await?;
            Ok::<_, DomainError>(Choices::new(
                names(state.lists()),
                names(state.profiles()),
                found.into_keys().collect(),
            ))
        };
        match read.await {
            Ok(choices) => choices,
            Err(error) => {
                let failure = plan_failure(Family::Changes, locale, &error);
                let shown = Outcome::failed(failure).render(locale);
                return Err(respond::retarget(shown, "#page-outcome").into());
            }
        }
    } else {
        Choices::default()
    };
    Ok(form
        .dialog(action.router(), locale, &choices)
        .values(values))
}
