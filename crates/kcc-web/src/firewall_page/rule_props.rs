//! The firewall dialogs of one rule's properties: Description and Schedule.
//!
//! Each names its rule by list, position and stored words and changes it only while a
//! fresh read still has that rule there; an empty description or Always removes the
//! property.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{RouterCtx, firewall::descriptor::DESCRIPTOR, schedules};
use kcc_i18n::{keys, locale::Locale};

use super::{
    checks::description,
    expect::Expect,
    lines,
    rule_actions::{Named, filtered},
    run::{Planned, Sender, find, located},
    views::Spot,
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        form::{Choice, FormDialog, Input},
        request::{Params, with_query},
        respond::Answer,
        submit::{Invalid, rejected::Rejected},
    },
    system_pages::shared::{merged, value},
};

/// A rule's description, audited as `web.firewall_rule_description`.
const DESCRIBE: Operation = Operation::write(&DESCRIPTOR, "rule", "web.firewall_rule_description");

/// A rule's schedule, audited as `web.firewall_rule_schedule`.
const SCHEDULE: Operation = Operation::write(&DESCRIPTOR, "rule", "web.firewall_rule_schedule");

/// `GET /ui/r/{router}/firewall/rule/description?list=&index=&rule=`: the description
/// dialog.
///
/// # Errors
///
/// Answers 404 for a malformed rule, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn description_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), Vec::new());
    let named = Named::from_pairs(&pairs)?;
    let opened = DESCRIBE.open(&state, &user, &router).await?;
    let domain = opened.context().await?;
    let (action, _firewall, entry) = located(opened, &domain, &named).await?;
    let current = entry.description().unwrap_or_default().to_owned();
    let values = Params::new(vec![("description".to_owned(), current)], Vec::new());
    Ok(description_form(action.locale(), (&router, &named, &pairs), &values).show())
}

/// `POST /ui/r/{router}/firewall/rule/description?...`: sets or removes the description.
///
/// # Errors
///
/// Answers the dialog with its field error (422), 404 for a malformed rule, 403 for a
/// management change the role may not make, and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn describe(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let named = Named::from_pairs(&pairs)?;
    let action = DESCRIBE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let values = Params::of(pairs.clone());
    let dialog = description_form(locale, (&router, &named, &pairs), &values);
    let path = format!("/ui/r/{router}/firewall/rule/description");
    let sender = Sender::new(&user, &headers, (&router, &path, &pairs));
    Ok(sender
        .submission(action, &values, dialog)
        .submit_reading(
            async |submitted, domain| {
                let text = description(submitted.text("description"))
                    .map_err(|rule| Invalid::at("description", rule))?;
                let (firewall, entry) = find(domain, &named, locale).await?;
                let identity = entry.configured().ok_or(Rejected::Missing)?;
                let planned =
                    lines::description(domain, named.list(), (&identity, text.as_deref()));
                Ok(planned.map(|request| {
                    let expect = Expect::Property {
                        list: named.list().to_owned(),
                        index: named.index(),
                        keyword: "description",
                        value: text,
                    };
                    Planned::new(request, expect, filtered(&firewall, named.list()))
                }))
            },
            async |planned, domain| sender.assess(domain, planned).await,
            async |domain| sender.refreshed(domain, Spot::Lists, locale).await,
        )
        .await)
}

/// `GET /ui/r/{router}/firewall/rule/schedule?list=&index=&rule=`: the schedule dialog.
///
/// # Errors
///
/// Answers 404 for a malformed rule, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn schedule_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), Vec::new());
    let named = Named::from_pairs(&pairs)?;
    let opened = SCHEDULE.open(&state, &user, &router).await?;
    let domain = opened.context().await?;
    let (action, _firewall, entry) = located(opened, &domain, &named).await?;
    let schedules = schedule_names(&domain).await;
    let current = entry.schedule().unwrap_or_default().to_owned();
    let values = Params::new(vec![("schedule".to_owned(), current)], Vec::new());
    let form = schedule_form(
        action.locale(),
        (&router, &named, &pairs),
        &values,
        &schedules,
    );
    Ok(form.show())
}

/// `POST /ui/r/{router}/firewall/rule/schedule?...`: sets or removes the schedule.
///
/// # Errors
///
/// Answers the dialog with its field error (422), 404 for a malformed rule, 403 for a
/// management change the role may not make, and what the kit answers when the router or
/// the permission is missing.
pub(crate) async fn schedule(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let named = Named::from_pairs(&pairs)?;
    let action = SCHEDULE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let schedules = schedule_names(&action.context().await?).await;
    let values = Params::of(pairs.clone());
    let dialog = schedule_form(locale, (&router, &named, &pairs), &values, &schedules);
    let path = format!("/ui/r/{router}/firewall/rule/schedule");
    let sender = Sender::new(&user, &headers, (&router, &path, &pairs));
    Ok(sender
        .submission(action, &values, dialog)
        .submit_reading(
            async |_submitted, domain| {
                let chosen = value(&pairs, "schedule").unwrap_or_default().to_owned();
                if !chosen.is_empty() && !schedules.contains(&chosen) {
                    return Err(Invalid::at("schedule", keys::WEB_ROUTING_ERROR_CHOICE).into());
                }
                let (firewall, entry) = find(domain, &named, locale).await?;
                let identity = entry.configured().ok_or(Rejected::Missing)?;
                let picked = Some(chosen).filter(|name| !name.is_empty());
                let planned = lines::schedule(domain, named.list(), (&identity, picked.as_deref()));
                Ok(planned.map(|request| {
                    let expect = Expect::Property {
                        list: named.list().to_owned(),
                        index: named.index(),
                        keyword: "schedule",
                        value: picked,
                    };
                    Planned::new(request, expect, filtered(&firewall, named.list()))
                }))
            },
            async |planned, domain| sender.assess(domain, planned).await,
            async |domain| sender.refreshed(domain, Spot::Lists, locale).await,
        )
        .await)
}

/// The router's schedule names; none when it does not say.
// cancel-safe: reads only.
async fn schedule_names(domain: &RouterCtx) -> Vec<String> {
    schedules::read_schedules(domain)
        .await
        .map_or_default(|found| found.into_iter().filter_map(|item| item.name).collect())
}

/// The address of the rule action `action` that `pairs` name on `router`.
fn rule_action(router: &str, action: &str, named: &Named, pairs: &[(String, String)]) -> String {
    let index = named.index().to_string();
    let words = value(pairs, "rule").unwrap_or_default();
    with_query(
        &format!("/ui/r/{router}/firewall/rule/{action}"),
        &[("list", named.list()), ("index", &index), ("rule", words)],
    )
}

/// The description dialog of the rule `named` on `router` with `values`.
fn description_form(
    locale: Locale,
    (router, named, pairs): (&str, &Named, &[(String, String)]),
    values: &Params,
) -> FormDialog {
    let title = named.title(locale, keys::WEB_FIREWALL_DESCRIPTION_TITLE);
    FormDialog::network(
        locale,
        title,
        rule_action(router, "description", named, pairs),
    )
    .submit(keys::COMMON_SAVE)
    .with_input(
        Input::new(
            "description",
            keys::WEB_ROUTING_FIELD_DESCRIPTION,
            values.text("description").to_owned(),
        )
        .max_chars(64)
        .optional()
        .help(keys::WEB_FIREWALL_HELP_DESCRIPTION)
        .rule(keys::WEB_FIREWALL_ERROR_DESCRIPTION),
    )
}

/// The schedule dialog of the rule `named` on `router` with `values` and the router's
/// `schedules`.
fn schedule_form(
    locale: Locale,
    (router, named, pairs): (&str, &Named, &[(String, String)]),
    values: &Params,
    schedules: &[String],
) -> FormDialog {
    let title = named.title(locale, keys::WEB_FIREWALL_SCHEDULE_TITLE);
    let mut choices = vec![Choice::word(locale, "", keys::WEB_FIREWALL_NO_SCHEDULE)];
    choices.extend(schedules.iter().map(|name| Choice::plain(name)));
    FormDialog::network(locale, title, rule_action(router, "schedule", named, pairs))
        .submit(keys::COMMON_SAVE)
        .with_input(
            Input::new(
                "schedule",
                keys::WEB_FIREWALL_COL_SCHEDULE,
                values.text("schedule").to_owned(),
            )
            .optional()
            .select(choices)
            .help(keys::WEB_FIREWALL_HELP_SCHEDULE),
        )
}
