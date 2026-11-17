//! The one-field dialogs of the Wi-Fi page: `GET` shows a setting's dialog with its
//! current value, `POST` checks the typed value, plans it with the Wi-Fi domain and runs it.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{DomainError, wifi};

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Subject, refreshed, unread, unread_change},
    net_pages::{Call, Tab},
    net_wifi_fields::Setting,
    page_kit::{
        change::Change,
        confirm::Resubmit,
        request::{Params, missing},
        respond::Answer,
        submit::{Invalid, Planned, Submission},
    },
};

/// `GET /ui/r/{router}/wifi/edit/{setting}?name=`: the dialog of one setting.
///
/// # Errors
///
/// Answers 404 for a setting the page does not edit or a missing name, and what the kit
/// answers when the router or the permission is missing.
pub(crate) async fn field_dialog(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let setting = Setting::from_slug(&slug).ok_or_else(missing)?;
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = setting.operation("").open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let unusable = |error: DomainError| unread(action.locale(), &error);
    let current = setting
        .current(&domain, &name)
        .await
        .map_err(unusable)?
        .unwrap_or_default();
    let choices = setting.choices(&domain).await.map_err(unusable)?;
    let subject = Subject::new(&router, &name, action.locale());
    Ok(setting.form(subject, current, &choices).show())
}

/// `POST /ui/r/{router}/wifi/edit/{setting}?name=`: checks the value, plans it with the
/// Wi-Fi domain and runs it.
///
/// # Errors
///
/// Answers the dialog with its field error (422) when the value is invalid, 404 for a
/// setting the page does not edit or a missing name, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn field(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let setting = Setting::from_slug(&slug).ok_or_else(missing)?;
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let typed = params.text("value");
    let action = setting
        .operation(typed)
        .open(&state, &user, &router)
        .await?;
    let subject = Subject::new(&router, &name, action.locale());
    let choices = match setting {
        Setting::Schedule | Setting::Width => {
            match setting.choices(&action.context().await?).await {
                Ok(found) => found,
                Err(error) => return Err(unread_change(action, &error).await),
            }
        }
        Setting::Ssid
        | Setting::Security
        | Setting::Channel
        | Setting::Power
        | Setting::Country => Vec::new(),
    };
    let dialog = setting
        .form(subject, typed.to_owned(), &choices)
        .refusing_at("value");
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Wifi);
    let resubmit = Resubmit::new(
        params.again(&format!("/ui/r/{router}/wifi/edit/{slug}")),
        "#page-outcome",
    );
    Ok(Submission::new(action, &params, dialog, resubmit)
        .submit(
            |submitted| {
                setting
                    .check(submitted.text("value"), &choices)
                    .map_err(|rule| Invalid::at("value", rule))
            },
            async |checked, domain| {
                let operation = checked.plan(domain, &name).await?;
                let request = wifi::change_request(&name, &operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
}
