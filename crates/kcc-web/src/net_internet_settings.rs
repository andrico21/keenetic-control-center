//! A connection's settings dialog on the internet page.
//!
//! It lists the connection's type, address, underlying connection, whether a user name and
//! a password are set, MTU, default route and priority, with Edit where the role may
//! change them, and the button that turns PPP's default route on or off.

use axum::{
    extract::{Path, Query, State},
    response::Response,
};
use kcc_domain::wan;
use kcc_i18n::keys;

use crate::{
    WebState,
    authz::CurrentUser,
    net_change::{Params, Subject, missing, reader, unusable},
    net_settings::{Button, Fact, SettingsDialog},
    net_wan::{Kind, Link, links},
    page_kit::{context::fragment_shell, family::Family, gate::Controls, respond::Answer},
};

/// `GET /ui/r/{router}/internet/settings?name=`: a connection's settings.
///
/// # Errors
///
/// Answers 404 for a missing or unknown connection, and the failure in the page's outcome
/// region when the router cannot be read.
// cancel-safe: reads only.
pub(crate) async fn settings(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let name = Params::new(query, Vec::new()).object("name")?;
    let (facts, domain) = reader(&state, &user, &router).await?;
    let link = links(&domain)
        .await
        .map_err(|_error| unusable(user.locale(), Family::Changes.unreachable()))?
        .into_iter()
        .find(|link| link.id() == name.as_str())
        .ok_or_else(missing)?;
    let controls = Controls::new(user.role(), &router)
        .with_operations(wan::DESCRIPTOR.write_ops, Some(facts.catalog()));
    let subject = Subject::new(&router, &name, user.locale());
    let mut dialog = SettingsDialog::new(
        fragment_shell(user.locale()),
        subject.title(keys::WEB_INTERNET_SETTINGS_TITLE),
        settings_facts(subject, &link, &controls),
    );
    if link.kind().is_some_and(Kind::ppp) && controls.allows("default_route") {
        let (wanted, label) = if link.default_route() == Some(true) {
            ("no", keys::WEB_INTERNET_DEFAULT_ROUTE_OFF)
        } else {
            ("yes", keys::WEB_INTERNET_DEFAULT_ROUTE_ON)
        };
        dialog = dialog.with_button(Button::new(
            subject.url("internet/default-route", &[("use", wanted)]),
            subject.text(label),
        ));
    }
    Ok(dialog.show())
}

/// The settings of `link`, with Edit where `controls` allow.
fn settings_facts(subject: Subject<'_>, link: &Link, controls: &Controls) -> Vec<Fact> {
    let locale = subject.locale();
    let edit = |operation: &str, action: &str| {
        controls.allows(operation).then(|| subject.url(action, &[]))
    };
    let fact = |id, key, value| Fact::new(id, subject.text(key), value);
    let ipoe = link.kind() == Some(Kind::Ipoe);
    let mut facts = vec![
        fact("wan-type", keys::WEB_INTERNET_KIND, link.kind_text(locale)),
        fact(
            "wan-address",
            keys::WEB_NETWORK_ADDRESS,
            link.address_text(locale),
        )
        .editable(edit("address_static", "internet/address").filter(|_| ipoe)),
    ];
    if link.kind().is_some_and(Kind::ppp) {
        let default_route = link.default_route().map(|used| {
            subject.text(if used {
                keys::COMMON_YES
            } else {
                keys::COMMON_NO
            })
        });
        facts.extend([
            fact(
                "wan-via",
                keys::WEB_INTERNET_VIA,
                link.via().map(str::to_owned),
            )
            .editable(edit("connect_via", "internet/edit/via")),
            fact(
                "wan-identity",
                keys::WEB_INTERNET_IDENTITY,
                Some(link.presence_text(locale, true)),
            )
            .editable(edit("identity", "internet/edit/identity")),
            fact(
                "wan-password",
                keys::WEB_INTERNET_PASSWORD,
                Some(link.presence_text(locale, false)),
            ),
            fact(
                "wan-default-route",
                keys::WEB_INTERNET_DEFAULT_ROUTE,
                default_route,
            ),
        ]);
    }
    facts.extend([
        fact("wan-mtu", keys::WEB_NETWORK_MTU, link.mtu_text())
            .editable(edit("mtu", "internet/edit/mtu")),
        fact(
            "wan-priority",
            keys::WEB_NETWORK_PRIORITY,
            link.priority().map(|priority| priority.to_string()),
        )
        .editable(edit("priority", "internet/edit/priority")),
    ]);
    facts
}
