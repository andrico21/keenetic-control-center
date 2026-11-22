//! The Entware settings changes and the removal.
//!
//! Chroot and the time zone are writes; turning chroot on first shows what the router
//! warns about. DNS override changes how the household resolves names and frees the
//! router's DNS port, so it is a management change: the kit asks first and runs it inside
//! the fail-safe timer. The startup script and the removal are destructive and need the
//! router name typed. Each change is planned by the Entware domain, which checks the
//! permission, the confirmation and the value grammar, and is read back after it ran.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use kcc_catalog::Risk;
use kcc_domain::entware::{self, models::TimezoneSetting};
use kcc_i18n::{bundle::tr, keys};

use super::{
    entware::Viewer,
    entware_change::{
        CHROOT, Course, DNS_OVERRIDE, INITRC, REMOVE, TIMEZONE, run, switch, warning,
    },
    shared::{merged, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        confirm::{Dialog, Resubmit, Words},
        request::{Params, with_query},
        respond::Answer,
    },
};

/// `POST /ui/r/{router}/system/entware/chroot?on=true|false`: turns chroot on or off;
/// turning it on first shows the warnings the domain planned with it.
///
/// # Errors
///
/// Answers 404 for an unknown value, and what the kit answers when the router or the
/// permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back
// or audit entry.
pub(crate) async fn chroot(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let enabled = switch(&pairs)?;
    let action = CHROOT.open(&state, &user, &router).await?;
    let word = if enabled { "true" } else { "false" };
    let path = format!("/ui/r/{router}/system/entware/chroot");
    let again = Resubmit::new(with_query(&path, &[("on", word)]), "#page-outcome");
    let confirmed = Params::of(pairs.clone()).confirmation().confirmed();
    let domain = action.context().await?;
    if let Ok(plan) = entware::plan_chroot(&domain, &router, user.role(), enabled)
        && !plan.warnings.is_empty()
        && !confirmed
    {
        let locale = action.locale();
        let text: Vec<String> = plan
            .warnings
            .iter()
            .map(|said| tr(locale, warning(*said), None))
            .collect();
        let words = Words::new(
            tr(locale, keys::WEB_SYSTEM_ENTWARE_WARNING_TITLE, None),
            text.join(" "),
            tr(locale, keys::WEB_KIT_CONFIRM, None),
        );
        return Ok(Dialog::new(locale, words, again).show());
    }
    let course = Course::new(again, Viewer::new(&user, &router));
    Ok(run(action, pairs, course, |ctx| {
        entware::plan_chroot(ctx, &router, user.role(), enabled)
    })
    .await)
}

/// `POST /ui/r/{router}/system/entware/timezone` with `timezone=auto|<name>`: sets the
/// time zone Entware runs with.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back
// or audit entry.
pub(crate) async fn timezone(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = TIMEZONE.open(&state, &user, &router).await?;
    let typed = value(&pairs, "timezone").unwrap_or_default().to_owned();
    let setting = if typed == "auto" {
        TimezoneSetting::Auto
    } else {
        TimezoneSetting::Named(typed.clone())
    };
    let path = format!("/ui/r/{router}/system/entware/timezone");
    let again = Resubmit::new(with_query(&path, &[("timezone", &typed)]), "#page-outcome");
    let course = Course::new(again, Viewer::new(&user, &router))
        .refusing_with(keys::WEB_SYSTEM_ENTWARE_TIMEZONE_RULE);
    Ok(run(action, pairs, course, |ctx| {
        entware::plan_timezone(ctx, &router, user.role(), setting)
    })
    .await)
}

/// `POST /ui/r/{router}/system/entware/initrc` with `path=/opt/...`: sets the script
/// Entware starts with, once the router name was typed.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back
// or audit entry.
pub(crate) async fn initrc(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let action = INITRC.open(&state, &user, &router).await?;
    let script = value(&pairs, "path").unwrap_or_default().to_owned();
    let path = format!("/ui/r/{router}/system/entware/initrc");
    let again = Resubmit::new(with_query(&path, &[("path", &script)]), "#page-outcome");
    let course = Course::new(again, Viewer::new(&user, &router))
        .asking_first(Risk::Destructive)
        .refusing_with(keys::WEB_SYSTEM_ENTWARE_INITRC_RULE);
    Ok(run(action, pairs, course, |ctx| {
        entware::plan_initrc(ctx, &router, user.role(), &script, true)
    })
    .await)
}

/// `POST /ui/r/{router}/system/entware/dns-override?on=true|false`: turns DNS override on
/// or off once the fail-safe timer was explained; it runs inside the timer.
///
/// # Errors
///
/// Answers 404 for an unknown value, and what the kit answers when the router or the
/// permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back,
// audit entry or timer cleanup.
pub(crate) async fn dns_override(
    State(state): State<WebState>,
    Path(router): Path<String>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let pairs = merged(query.as_deref(), form);
    let enabled = switch(&pairs)?;
    let action = DNS_OVERRIDE.open(&state, &user, &router).await?;
    let word = if enabled { "true" } else { "false" };
    let path = format!("/ui/r/{router}/system/entware/dns-override");
    let again = Resubmit::new(with_query(&path, &[("on", word)]), "#page-outcome");
    let course = Course::new(again, Viewer::new(&user, &router)).asking_first(Risk::Management);
    Ok(run(action, pairs, course, |ctx| {
        entware::plan_dns_override(ctx, &router, user.role(), enabled)
    })
    .await)
}

/// `POST /ui/r/{router}/system/entware/remove`: clears `opkg disk` once the router name
/// was typed.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
// NOT cancel-safe: dropped after the change is sent, the router may keep it without its read-back
// or audit entry.
pub(crate) async fn remove(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = REMOVE.open(&state, &user, &router).await?;
    let again = Resubmit::new(
        format!("/ui/r/{router}/system/entware/remove"),
        "#page-outcome",
    );
    let course = Course::new(again, Viewer::new(&user, &router)).asking_first(Risk::Destructive);
    Ok(run(action, pairs, course, |ctx| {
        entware::plan_remove(ctx, &router, user.role(), true)
    })
    .await)
}
