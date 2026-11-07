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
use kcc_i18n::{bundle::tr, keys};
use kcc_rci::ObjectName;

use super::{
    frame::interface_names,
    policy_change::{NameQuery, find, known, planned_change},
    policy_dialogs::{create_form, description_form, permit_form, word},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Params, missing},
    page_kit::{action::Operation, failure::plan_failure, family::Family, respond::Answer},
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
    let refuse = |field: &str, message: String| {
        create_form(locale, &router, &values)
            .with_error(field, message)
            .invalid()
    };
    let name = values.text("name").trim().to_owned();
    let checked = if name.parse::<ObjectName>().is_err() {
        Err(("name", keys::WEB_ROUTING_ERROR_NAME))
    } else {
        word(values.text("description")).map_err(|key| ("description", key))
    };
    let description = match checked {
        Ok(found) => found,
        Err((field, key)) => {
            action.abandon("validation_failed").await;
            return Err(refuse(field, tr(locale, key, None)).into());
        }
    };
    let domain = action.context().await?;
    if find(&domain, &name).await.is_some() {
        action.abandon("validation_failed").await;
        let message = tr(locale, keys::WEB_ROUTING_ERROR_POLICY_EXISTS, None);
        return Err(refuse("name", message).into());
    }
    let planned = plan::create(&domain, &name).and_then(|created| {
        let mut ops = vec![created];
        if let Some(text) = &description {
            ops.push(plan::description(&domain, &name, Some(text))?);
        }
        Ok(ops)
    });
    match planned {
        Ok(ops) => Ok(planned_change(action, &domain, Ok(ops), (&headers, &user)).await),
        Err(error) => {
            action.abandon("validation_failed").await;
            let failure = plan_failure(Family::Changes, locale, &error);
            Err(refuse("name", failure.message().to_owned()).into())
        }
    }
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
    let opened = DESCRIBE.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let domain = opened.context().await?;
    let (action, policy) = known(opened, &domain, query.name()).await?;
    let values = Params::new(Vec::new(), pairs);
    let description = match word(values.text("description")) {
        Ok(found) => found,
        Err(key) => {
            action.abandon("validation_failed").await;
            let dialog = description_form(locale, &router, policy.name(), &values);
            return Err(dialog
                .with_error("description", tr(locale, key, None))
                .invalid()
                .into());
        }
    };
    let planned = plan::description(&domain, policy.name(), description.as_deref());
    Ok(planned_change(
        action,
        &domain,
        planned.map(|op| vec![op]),
        (&headers, &user),
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
    let opened = PERMIT.open(&state, &user, &router).await?;
    let locale = opened.locale();
    let domain = opened.context().await?;
    let (action, policy) = known(opened, &domain, query.name()).await?;
    let names = interface_names(&domain).await;
    let values = Params::new(Vec::new(), pairs);
    let interface = values.text("interface").trim().to_owned();
    let order = values.text("order").trim();
    let checked = if names.contains(&interface) {
        if order.is_empty() {
            Ok(PolicyPermit::new(&interface))
        } else {
            order
                .parse::<u16>()
                .map(|number| PolicyPermit::new(&interface).with_order(u32::from(number)))
                .map_err(|_error| ("order", keys::WEB_ROUTING_ERROR_NUMBER))
        }
    } else {
        Err(("interface", keys::WEB_ROUTING_ERROR_CHOICE))
    };
    let allowed = match checked {
        Ok(found) => found,
        Err((field, key)) => {
            action.abandon("validation_failed").await;
            let dialog = permit_form(locale, (&router, policy.name()), &values, &names);
            return Err(dialog
                .with_error(field, tr(locale, key, None))
                .invalid()
                .into());
        }
    };
    let planned = plan::permit(&domain, policy.name(), &allowed, true);
    Ok(planned_change(
        action,
        &domain,
        planned.map(|op| vec![op]),
        (&headers, &user),
    )
    .await)
}
