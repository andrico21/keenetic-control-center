//! The removals and the address translation of the port forwarding page: a rule removed
//! after a plain confirmation, an interface given address translation or taken off it.

use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::{
    RouterCtx,
    nat::{change, descriptor::DESCRIPTOR, read},
};
use kcc_i18n::{bundle::tr, keys, locale::Locale};
use serde::Deserialize;

use super::{
    forward_forms::{applied, rules},
    forwards::{Forward, forwards},
    interfaces::{InterfacesRegion, interfaces_region, nat_interfaces},
};
use crate::{
    WebState,
    authz::CurrentUser,
    markup::Rendered,
    net_change::unusable,
    page_kit::{
        action::Operation,
        confirm::Resubmit,
        form::{Choice, FormDialog, Input},
        request::{Params, missing, rendered, shown_query, with_query},
        respond::Answer,
        submit::{Formless, Invalid, Submission},
    },
    routing_page::{
        frame::interface_names,
        reply::{ConfirmDialog, Replying, gone, refused, unread},
    },
};

/// A rule removed, audited as `web.nat_forward_remove`.
const REMOVE: Operation = Operation::write(&DESCRIPTOR, "forward", "web.nat_forward_remove");

/// Address translation added, audited as `web.nat_interface_add`.
const TRANSLATE: Operation = Operation::write(&DESCRIPTOR, "interface", "web.nat_interface_add");

/// Address translation removed, audited as `web.nat_interface_remove`.
const UNTRANSLATE: Operation =
    Operation::write(&DESCRIPTOR, "interface", "web.nat_interface_remove");

/// The rule a removal names, as the rules table links it.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ForwardQuery {
    /// Protocol keyword.
    #[serde(default)]
    protocol: Option<String>,
    /// Incoming interface.
    #[serde(default)]
    interface: String,
    /// First external port.
    #[serde(default)]
    port: Option<u16>,
    /// Last external port.
    #[serde(default)]
    end: Option<u16>,
    /// The device forwarded to.
    #[serde(default)]
    target: String,
    /// The port there.
    #[serde(default)]
    to: Option<u16>,
}

impl ForwardQuery {
    /// The rule named.
    fn rule(&self) -> Forward {
        Forward::new(
            (self.protocol.clone(), self.interface.clone()),
            (self.port, self.end),
            (self.target.clone(), self.to),
        )
    }
}

/// The interface an action names.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct NameQuery {
    /// The interface.
    #[serde(default)]
    name: String,
}

/// `GET /ui/r/{router}/nat/forward/remove?...`: asks first.
///
/// # Errors
///
/// Answers 404 for a rule the NAT domain cannot express, and what the kit answers when
/// the router or the permission is missing.
pub(crate) async fn remove_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<ForwardQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let rule = query.rule();
    if rule.domain_rule().is_none() {
        return Err(missing());
    }
    let action = REMOVE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let title = tr(locale, keys::WEB_NAT_REMOVE_TITLE, None);
    let url = remove_url(&router, &rule);
    Ok(ConfirmDialog::new(locale, title, keys::WEB_NAT_REMOVE_TEXT, url).show())
}

/// `POST /ui/r/{router}/nat/forward/remove?...`: removes the rule and reads it back.
///
/// # Errors
///
/// Answers 404 for a rule the NAT domain cannot express, and what the kit answers when
/// the router or the permission is missing.
pub(crate) async fn remove(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<ForwardQuery>,
    headers: HeaderMap,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let rule = query.rule();
    let planned = rule.domain_rule().ok_or_else(missing)?;
    let action = REMOVE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let params = Params::default();
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/nat/forward/remove"),
        "#page-outcome",
    );
    Ok(
        Submission::new(action, &params, Replying::new(Formless), resubmit)
            .submit_reading(
                async |_params, domain| {
                    let known = read::running_forwards(domain)
                        .await
                        .map_err(|_error| unread(locale, keys::WEB_KIT_UNREACHABLE))?;
                    if forwards(&known).contains(&rule) {
                        Ok(())
                    } else {
                        Err(gone(locale).into())
                    }
                },
                async |(), domain| Ok(applied(change::plan_remove_forward(domain, &planned)?)),
                async |domain| rules(domain, &router, &headers, locale).await,
            )
            .await,
    )
}

/// `GET /ui/r/{router}/nat/interface/new`: the dialog choosing an interface.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn translate_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = TRANSLATE.open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let names = interface_names(&domain)
        .await
        .map_err(|message| unusable(action.locale(), message))?;
    Ok(translate_form(action.locale(), &router, "", &names).show())
}

/// `POST /ui/r/{router}/nat/interface/new`: gives the interface address translation.
///
/// # Errors
///
/// Answers the dialog with its field error (422), and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn translate(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = TRANSLATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let names = match interface_names(&action.context().await?).await {
        Ok(found) => found,
        Err(message) => return Ok(refused(action, unread(locale, message)).await),
    };
    let values = Params::new(Vec::new(), pairs);
    let interface = values.text("interface").trim().to_owned();
    let dialog = Replying::new(translate_form(locale, &router, &interface, &names));
    let resubmit = Resubmit::new(format!("/ui/r/{router}/nat/interface/new"), "#page-outcome");
    Ok(Submission::new(action, &values, dialog, resubmit)
        .submit_reading(
            async |_values, domain| {
                let translated = nat_interfaces(domain)
                    .await
                    .map_err(|message| unread(locale, message))?;
                if !names.contains(&interface) {
                    Err(Invalid::at("interface", keys::WEB_ROUTING_ERROR_CHOICE).into())
                } else if translated.contains(&interface) {
                    Err(Invalid::at("interface", keys::WEB_ROUTING_ERROR_DUPLICATE).into())
                } else {
                    Ok(())
                }
            },
            async |(), domain| Ok(applied(change::plan_add_interface(domain, &interface)?)),
            async |domain| interfaces(domain, &router, &headers, locale).await,
        )
        .await)
}

/// `GET /ui/r/{router}/nat/interface/remove?name=`: asks first.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn untranslate_dialog(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<NameQuery>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = UNTRANSLATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let mut args = FluentArgs::new();
    args.set("name", query.name.clone());
    let title = tr(locale, keys::WEB_NAT_INTERFACE_REMOVE_TITLE, Some(&args));
    let url = with_query(
        &format!("/ui/r/{router}/nat/interface/remove"),
        &[("name", &query.name)],
    );
    Ok(ConfirmDialog::new(locale, title, keys::WEB_NAT_INTERFACE_REMOVE_TEXT, url).show())
}

/// `POST /ui/r/{router}/nat/interface/remove?name=`: takes address translation off the
/// interface.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn untranslate(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<NameQuery>,
    headers: HeaderMap,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let action = UNTRANSLATE.open(&state, &user, &router).await?;
    let locale = action.locale();
    let params = Params::default();
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/nat/interface/remove"),
        "#page-outcome",
    );
    Ok(
        Submission::new(action, &params, Replying::new(Formless), resubmit)
            .submit_reading(
                async |_params, domain| {
                    let translated = nat_interfaces(domain)
                        .await
                        .map_err(|message| unread(locale, message))?;
                    if translated.contains(&query.name) {
                        Ok(())
                    } else {
                        Err(gone(locale).into())
                    }
                },
                async |(), domain| Ok(applied(change::plan_remove_interface(domain, &query.name)?)),
                async |domain| interfaces(domain, &router, &headers, locale).await,
            )
            .await,
    )
}

/// The interfaces region of `router` read back for the page of `headers`, out of band.
// cancel-safe: reads only.
async fn interfaces(
    domain: &RouterCtx,
    router: &str,
    headers: &HeaderMap,
    locale: Locale,
) -> Option<Rendered> {
    interfaces_region(domain, (router, &shown_query(headers)), (true, locale))
        .await
        .ok()
        .map(InterfacesRegion::out_of_band)
        .and_then(|region| rendered(&region))
}

/// The address of the removal of `rule` on `router`.
fn remove_url(router: &str, rule: &Forward) -> String {
    let pairs = rule.pairs();
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    with_query(&format!("/ui/r/{router}/nat/forward/remove"), &borrowed)
}

/// The dialog choosing an interface for address translation on `router`, `chosen`
/// selected, with the router's interface `names`.
fn translate_form(locale: Locale, router: &str, chosen: &str, names: &[String]) -> FormDialog {
    let title = tr(locale, keys::WEB_NAT_INTERFACE_ADD_TITLE, None);
    let choices = names.iter().map(|name| Choice::plain(name)).collect();
    FormDialog::network(locale, title, format!("/ui/r/{router}/nat/interface/new"))
        .submit(keys::WEB_NAT_INTERFACE_ADD)
        .with_input(
            Input::new(
                "interface",
                keys::WEB_ROUTING_FIELD_INTERFACE,
                chosen.to_owned(),
            )
            .select(choices)
            .help(keys::WEB_NAT_INTERFACE_ADD_TEXT),
        )
}
