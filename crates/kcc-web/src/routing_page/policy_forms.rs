//! The dialogs of the connection policies: Add policy, Description and Add interface.
//!
//! Add policy takes a name and an optional one-word description, Add interface an
//! interface and its optional order. The policies domain plans each change and reads it
//! back from `show rc`.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::policies::{change::plan, descriptor::DESCRIPTOR, model::PolicyPermit};
use kcc_i18n::keys;
use kcc_rci::ObjectName;

use super::{
    frame::interface_names,
    policy_change::{NameQuery, applied, find, known, refreshed, submission},
    policy_dialogs::{create_form, description_form, permit_form, word},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        action::Operation,
        confirm::Resubmit,
        request::{Params, missing},
        respond::Answer,
        submit::Invalid,
    },
};

/// Adding a policy, audited as `web.routing_policy_create`.
const CREATE: Operation = Operation::write(&DESCRIPTOR, "policy", "web.routing_policy_create");

/// A policy's description, audited as `web.routing_policy_description`.
const DESCRIBE: Operation =
    Operation::write(&DESCRIPTOR, "description", "web.routing_policy_description");

/// An interface permitted, audited as `web.routing_policy_permit`.
const PERMIT: Operation = Operation::write(&DESCRIPTOR, "permit", "web.routing_policy_permit");

/// `GET /ui/r/{router}/routing/policy/new`: the Add policy dialog.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn create_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = CREATE.open(&state, &user, &router).await?;
    Ok(create_form(action.locale(), &router, &Params::default()).show())
}

/// `POST /ui/r/{router}/routing/policy/new`: adds the policy and its description.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn create(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = CREATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let values = Params::new(Vec::new(), pairs);
    let name = values.text("name").trim().to_owned();
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/routing/policy/new"),
        "#page-outcome",
    );
    Ok(submission(
        action,
        (&values, resubmit),
        create_form(locale, &router, &values),
    )
    .submit_reading(
        async |submitted, domain| {
            if name.parse::<ObjectName>().is_err() {
                return Err(Invalid::at("name", keys::WEB_ROUTING_ERROR_NAME).into());
            }
            let description = word(submitted.text("description"))
                .map_err(|rule| Invalid::at("description", rule))?;
            if find(domain, &name).await.is_some() {
                return Err(Invalid::at("name", keys::WEB_ROUTING_ERROR_POLICY_EXISTS).into());
            }
            Ok(description)
        },
        async |description, domain| {
            let mut ops = vec![plan::create(domain, &name)?];
            if let Some(text) = &description {
                ops.push(plan::description(domain, &name, Some(text))?);
            }
            Ok(applied(ops))
        },
        async |domain| refreshed(domain, (&router, &user), &headers, locale).await,
    )
    .await)
}

/// `GET /ui/r/{router}/routing/policy/description?name=`: the description dialog.
///
/// # Errors
///
/// Answers 404 for a policy the router does not have, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn description_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = DESCRIBE.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let policy = find(&domain, query.name()).await.ok_or_else(missing)?;
    let values = policy.description().map_or_else(Params::default, |text| {
        Params::new(
            vec![("description".to_owned(), text.to_owned())],
            Vec::new(),
        )
    });
    Ok(description_form(action.locale(), &router, policy.name(), &values).show())
}

/// `POST /ui/r/{router}/routing/policy/description?name=`: sets or clears the description.
///
/// # Errors
///
/// Answers the dialog with its field error (422), 404 for a policy the router does not
/// have, and what the kit answers when the router or the permission is missing.
pub(crate) async fn describe(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<NameQuery>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = DESCRIBE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let values = Params::new(Vec::new(), pairs);
    let dialog = description_form(locale, &router, query.name(), &values);
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/routing/policy/description"),
        "#page-outcome",
    );
    Ok(submission(action, (&values, resubmit), dialog)
        .submit_reading(
            async |submitted, domain| {
                let policy = known(domain, query.name(), locale).await?;
                let description = word(submitted.text("description"))
                    .map_err(|rule| Invalid::at("description", rule))?;
                Ok((policy, description))
            },
            async |(policy, description), domain| {
                let op = plan::description(domain, policy.name(), description.as_deref())?;
                Ok(applied(vec![op]))
            },
            async |domain| refreshed(domain, (&router, &user), &headers, locale).await,
        )
        .await)
}

/// `GET /ui/r/{router}/routing/policy/permit?name=`: the Add interface dialog.
///
/// # Errors
///
/// Answers 404 for a policy the router does not have, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn permit_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = PERMIT.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let policy = find(&domain, query.name()).await.ok_or_else(missing)?;
    let names = interface_names(&domain).await;
    let form = permit_form(
        action.locale(),
        (&router, policy.name()),
        &Params::default(),
        &names,
    );
    Ok(form.show())
}

/// `POST /ui/r/{router}/routing/policy/permit?name=`: permits the interface at its order.
///
/// # Errors
///
/// Answers the dialog with its field errors (422), 404 for a policy the router does not
/// have, and what the kit answers when the router or the permission is missing.
pub(crate) async fn permit(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<NameQuery>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = PERMIT.open(&state, &user, &router).await?;
    let locale = action.locale();
    let names = interface_names(&action.context().await?).await;
    let values = Params::new(Vec::new(), pairs);
    let dialog = permit_form(locale, (&router, query.name()), &values, &names);
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/routing/policy/permit"),
        "#page-outcome",
    );
    Ok(submission(action, (&values, resubmit), dialog)
        .submit_reading(
            async |submitted, domain| {
                let policy = known(domain, query.name(), locale).await?;
                let interface = submitted.text("interface").trim();
                if !names.iter().any(|name| name == interface) {
                    return Err(Invalid::at("interface", keys::WEB_ROUTING_ERROR_CHOICE).into());
                }
                let order = submitted.text("order").trim();
                let allowed = if order.is_empty() {
                    PolicyPermit::new(interface)
                } else {
                    let number = order
                        .parse::<u16>()
                        .map_err(|_error| Invalid::at("order", keys::WEB_ROUTING_ERROR_NUMBER))?;
                    PolicyPermit::new(interface).with_order(u32::from(number))
                };
                Ok((policy, allowed))
            },
            async |(policy, allowed), domain| {
                Ok(applied(vec![plan::permit(
                    domain,
                    policy.name(),
                    &allowed,
                    true,
                )?]))
            },
            async |domain| refreshed(domain, (&router, &user), &headers, locale).await,
        )
        .await)
}
