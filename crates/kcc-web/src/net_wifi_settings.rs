//! A radio's or an access point's settings on the Wi-Fi page, and the access points'
//! switches.
//!
//! The settings dialog lists a radio's band, channel, width, power and country, or an
//! access point's network name, security, whether a Wi-Fi password is set, whether the
//! name is hidden, its state, schedule and segment, with Edit where the role may change
//! them (`net_wifi_fields`), and the buttons that enable or disable an access point and
//! hide or show its name.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_domain::{DomainError, wifi};
use kcc_i18n::keys;

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Subject, reader, refreshed, unusable},
    net_pages::{Call, Tab},
    net_settings::{Button, Fact, SettingsDialog},
    net_wifi_rows::{ApRow, RadioRow, access_points, radios},
    page_kit::{
        action::Operation,
        change::Change,
        confirm::Resubmit,
        context::fragment_shell,
        gate::Controls,
        read_failure::domain_problem,
        request::{Params, missing},
        respond::Answer,
        submit::{Formless, Planned, Submission},
    },
};

/// Enabling or disabling an access point, audited as `web.wifi_enabled`.
const UP: Operation = Operation::write(&wifi::DESCRIPTOR, "up", "web.wifi_enabled");

/// Hiding or showing a network name, audited as `web.wifi_hide_ssid`.
const HIDE: Operation = Operation::write(&wifi::DESCRIPTOR, "hide_ssid", "web.wifi_hide_ssid");

/// `GET /ui/r/{router}/wifi/settings?name=`: a radio's or an access point's settings.
///
/// # Errors
///
/// Answers 404 for a missing or unknown name, and the failure in the page's outcome
/// region when the router cannot be read.
// NOT cancel-safe: it may sign in first, and a sign-in dropped mid-way can leave an orphaned router
// session. Apart from that, reads only.
pub(crate) async fn settings(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let (facts, domain) = reader(&state, &user, &router).await?;
    let controls = Controls::new(user.role(), &router)
        .with_operations(wifi::DESCRIPTOR.write_ops, Some(facts.catalog()));
    let subject = Subject::new(&router, &name, user.locale());
    let unread = |error: DomainError| unusable(user.locale(), &domain_problem(&error));
    let radio = radios(&domain)
        .await
        .map_err(unread)?
        .into_iter()
        .find(|found| found.id() == name.as_str());
    if let Some(found) = radio {
        return Ok(radio_dialog(subject, &found, &controls).show());
    }
    let point = access_points(&domain)
        .await
        .map_err(unread)?
        .into_iter()
        .find(|found| found.id() == name.as_str())
        .ok_or_else(missing)?;
    Ok(point_dialog(subject, &point, &controls).show())
}

/// The settings dialog of `radio`, with Edit where `controls` allow.
fn radio_dialog(subject: Subject<'_>, radio: &RadioRow, controls: &Controls) -> SettingsDialog {
    let edit = |operation: &str, setting: &str| {
        controls
            .allows(operation)
            .then(|| subject.url(&format!("wifi/edit/{setting}"), &[]))
    };
    let fact =
        |id, key, value: Option<&str>| Fact::new(id, subject.text(key), value.map(str::to_owned));
    SettingsDialog::new(
        fragment_shell(subject.locale()),
        subject.title(keys::WEB_WIFI_RADIO_TITLE),
        vec![
            fact("radio-band", keys::WEB_WIFI_BAND, radio.band()),
            fact("radio-channel", keys::WEB_WIFI_CHANNEL, radio.channel())
                .editable(edit("channel", "channel")),
            fact("radio-width", keys::WEB_WIFI_WIDTH, radio.width())
                .editable(edit("channel_width", "width")),
            fact("radio-power", keys::WEB_WIFI_POWER, radio.power())
                .editable(edit("power", "power")),
            fact("radio-country", keys::WEB_WIFI_COUNTRY, radio.country())
                .editable(edit("country_code", "country")),
        ],
    )
}

/// The settings dialog of `point`, with Edit and the switches where `controls` allow.
fn point_dialog(subject: Subject<'_>, point: &ApRow, controls: &Controls) -> SettingsDialog {
    let locale = subject.locale();
    let edit = |operation: &str, setting: &str| {
        controls
            .allows(operation)
            .then(|| subject.url(&format!("wifi/edit/{setting}"), &[]))
    };
    let fact = |id, key, value: Option<String>| Fact::new(id, subject.text(key), value);
    let security = ["encryption_wpa2", "encryption_wpa3", "encryption_enable"]
        .into_iter()
        .find(|operation| controls.allows(operation))
        .and_then(|operation| edit(operation, "security"));
    let mut dialog = SettingsDialog::new(
        fragment_shell(locale),
        subject.title(keys::WEB_WIFI_AP_TITLE),
        vec![
            fact(
                "ap-ssid",
                keys::DOMAINS_WIFI_SSID,
                point.ssid().map(str::to_owned),
            )
            .editable(edit("ssid", "ssid")),
            fact(
                "ap-security",
                keys::WEB_WIFI_SECURITY,
                point.security().map(str::to_owned),
            )
            .editable(security),
            fact(
                "ap-password",
                keys::WEB_WIFI_PSK,
                Some(point.password_text(locale)),
            )
            .editable(
                controls
                    .allows("wpa_psk")
                    .then(|| subject.url("wifi/psk", &[])),
            ),
            fact(
                "ap-hidden",
                keys::WEB_WIFI_HIDDEN,
                point.hidden_text(locale),
            ),
            fact("ap-state", keys::WEB_WIFI_STATE, point.state_text(locale)),
            fact(
                "ap-schedule",
                keys::WEB_WIFI_SCHEDULE,
                point.schedule().map(str::to_owned),
            )
            .editable(edit("schedule", "schedule")),
            fact(
                "ap-segment",
                keys::WEB_WIFI_SEGMENT,
                point.segment().map(str::to_owned),
            ),
        ],
    );
    if controls.allows("hide_ssid") {
        let hide = point.hidden() != Some(true);
        let label = if hide {
            keys::WEB_WIFI_HIDE
        } else {
            keys::WEB_WIFI_SHOW
        };
        dialog = dialog.with_button(Button::new(
            subject.url(
                "wifi/toggle",
                &[("setting", "hidden"), ("value", yes_no(hide))],
            ),
            subject.text(label),
        ));
    }
    if controls.allows("up") {
        let enable = point.enabled() == Some(false);
        let label = if enable {
            keys::WEB_NETWORK_ENABLE
        } else {
            keys::WEB_NETWORK_DISABLE
        };
        dialog = dialog.with_button(Button::new(
            subject.url(
                "wifi/toggle",
                &[("setting", "enabled"), ("value", yes_no(enable))],
            ),
            subject.text(label),
        ));
    }
    dialog
}

/// `yes` or `no`.
const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// `POST /ui/r/{router}/wifi/toggle?name=&setting=enabled|hidden&value=yes|no`: enables or
/// disables an access point, or hides or shows its network name.
///
/// # Errors
///
/// Answers 404 for a missing name, switch or value, and what the kit answers when the
/// router or the permission is missing.
// NOT cancel-safe: dropped after `submit` sends the change, the router may keep it without its
// read-back, audit entry or timer cleanup.
pub(crate) async fn toggle(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(query, form);
    let name = params.object("name")?;
    let value = match params.get("value") {
        Some("yes") => true,
        Some("no") => false,
        Some(_) | None => return Err(missing()),
    };
    let (operation, hide) = match params.get("setting") {
        Some("enabled") => (UP, false),
        Some("hidden") => (HIDE, true),
        Some(_) | None => return Err(missing()),
    };
    let action = operation.open(&state, &user, &router).await?;
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Wifi);
    let resubmit = Resubmit::new(
        params.again(&format!("/ui/r/{router}/wifi/toggle")),
        "#page-outcome",
    );
    Ok(Submission::new(action, &params, Formless, resubmit)
        .submit(
            |_params| Ok(()),
            async |(), domain| {
                let planned = if hide {
                    wifi::plan_hide_ssid(domain, &name, value)?
                } else {
                    wifi::plan_up(domain, &name, value).await?
                };
                let request = wifi::change_request(&name, &planned)?;
                Ok(Planned::of(&[planned], Change::Cli(request)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
}
