//! A refused htmx request, answered where its result belongs.
//!
//! The 403 page is a whole page, which htmx does not show for a 4xx answer, so a refused
//! request used to change nothing on the screen. A handler that knows the region of its
//! result answers with this fragment instead: the request was not sent, the permissions
//! the role lacks on the router (by the names of the Roles page) and who can grant them.
//! The status stays 403; `HX-Retarget` names the region, which `app.js` reads as "swap
//! this like a 422". Any other 403 to an htmx request shows the page's refusal toast.

use alloc::collections::BTreeSet;

use askama::Template;
use axum::{http::StatusCode, response::Response};
use fluent_bundle::FluentArgs;
use kcc_app::permissions::Permission;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use crate::{
    admin_roles::permission_list,
    authz::CurrentUser,
    errors,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::allowed, outcome::with_status, respond},
};

/// The refusal fragment.
#[derive(Template)]
#[template(path = "partials/refusal.html")]
struct Fragment {
    /// Locale carrier.
    shell: Shell,
    /// The sentence naming the missing permissions.
    missing: String,
}

localized!(Fragment);

/// The permissions of `needed` that `user` does not hold on `router`.
pub(crate) fn missing(
    user: &CurrentUser,
    router: &str,
    needed: &[Permission],
) -> BTreeSet<Permission> {
    needed
        .iter()
        .copied()
        .filter(|permission| !allowed(user, router, &[*permission]))
        .collect()
}

/// The 403 refusal of a request whose role lacks `missing` (not empty) on the router.
///
/// It is in `locale` and meant for the result region `region`, a selector such as
/// `#cli-result`. The shared dialog closes, so the refusal of a confirmed request is not
/// hidden by it.
pub(crate) fn refused(
    locale: Locale,
    missing: &BTreeSet<Permission>,
    region: &'static str,
) -> Response {
    let mut args = FluentArgs::new();
    args.set("count", missing.len());
    args.set("permissions", permission_list(locale, missing));
    let fragment = errors::render(&Fragment {
        shell: fragment_shell(locale),
        missing: tr(locale, keys::WEB_REFUSAL_MISSING, Some(&args)),
    });
    respond::close_dialog(respond::retarget(
        with_status(fragment, StatusCode::FORBIDDEN),
        region,
    ))
}
