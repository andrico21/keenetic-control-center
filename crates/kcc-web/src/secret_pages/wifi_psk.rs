//! The Wi-Fi password of an access point: 8 to 63 characters, checked by the browser and
//! again here before anything is sent.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::wifi;
use kcc_i18n::{keys, locale::Locale};
use kcc_rci::ObjectName;

use super::{
    dialog::{Length, SecretDialog, entry},
    reply::{Secret, typed, unchanged},
};
use crate::{
    WebState,
    authz::CurrentUser,
    net_change::unusable,
    net_pages::{Call, Tab},
    net_wifi,
    net_wifi_rows::access_points,
    page_kit::{
        action::Operation,
        change::Change,
        confirm::Resubmit,
        family::Family,
        request::{Params, missing, with_query},
        respond::Answer,
        submit::{Planned, Submission},
    },
};

/// Setting an access point's Wi-Fi password, audited as `web.wifi_psk`.
const PSK: Operation = Operation::write(&wifi::DESCRIPTOR, "wpa_psk", "web.wifi_psk");

/// A WPA passphrase: 8 to 63 characters.
const LENGTH: Length = Length::new(8, 63, keys::WEB_SECRET_WIFI_RULE);

/// The dialog of the access point `name` on `router`.
fn dialog(router: &str, name: &ObjectName, locale: Locale) -> SecretDialog {
    let post_to = with_query(
        &format!("/ui/r/{router}/wifi/psk"),
        &[("name", name.as_str())],
    );
    SecretDialog::new(
        locale,
        (keys::WEB_SECRET_WIFI_TITLE, name.as_str()),
        post_to,
        (keys::WEB_SECRET_NEW_PASSWORD, keys::WEB_SECRET_WIFI_HELP),
    )
    .intro(keys::WEB_SECRET_WIFI_INTRO)
    .bounded(LENGTH)
}

/// `GET /ui/r/{router}/wifi/psk?name=`: the dialog; it never holds the stored password.
///
/// # Errors
///
/// Answers 404 for a missing name, and what the kit answers when the router or the
/// permission is missing.
pub(crate) async fn psk_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = PSK.open(&state, &user, &router).await?;
    Ok(dialog(&router, &name, action.locale()).show())
}

/// `POST /ui/r/{router}/wifi/psk?name=`: sets the password typed twice in the form body;
/// a wrong length or a mismatch comes back into the dialog before anything is sent.
///
/// # Errors
///
/// Answers 404 for a missing or unknown access point, the dialog with its error (422),
/// and what the kit answers when the router or the permission is missing.
pub(crate) async fn psk(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(mut form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let action = PSK.open(&state, &user, &router).await?;
    let locale = action.locale();
    let Some(typed) = typed(entry(&mut form)) else {
        return Ok(unchanged(action).await);
    };
    let checked = typed.and_then(|secret| LENGTH.checked(secret));
    if checked.is_ok() {
        let domain = action.context().await?;
        match access_points(&domain).await {
            Ok(points) if points.iter().any(|point| point.id() == name.as_str()) => {}
            Ok(_) => {
                action.abandon("not_found").await;
                return Err(missing());
            }
            Err(_) => {
                action.abandon("unreachable").await;
                return Err(unusable(locale, Family::Changes.unreachable()));
            }
        }
    }
    let shown = Secret::replacing(dialog(&router, &name, locale), keys::WEB_WIFI_PSK);
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Wifi);
    let params = Params::default();
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{router}/wifi/psk"),
            &[("name", name.as_str())],
        ),
        "#page-outcome",
    );
    Ok(Submission::new(action, &params, shown, resubmit)
        .submit(
            |_params| checked,
            async |secret, ctx| {
                let operation = wifi::plan_wpa_psk(ctx, &name, secret)?;
                let request = wifi::change_request(&name, &operation)?;
                Ok(Planned::of(&[operation], Change::Cli(request)))
            },
            async |ctx| net_wifi::refreshed(call, ctx).await,
        )
        .await)
}
