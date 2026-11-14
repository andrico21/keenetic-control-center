//! The router picker of a section about one router: the routers the role may read, each
//! with a link to the section's page on it.

use askama::Template;
use axum::response::Response;
use kcc_i18n::{bundle::MessageKey, keys};

use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
};

/// The picker page.
#[derive(Template)]
#[template(path = "pages/navpicker.html")]
struct Picker {
    /// Page shell, its section marked current.
    shell: Shell,
    /// The section's name, the page title and each router's link.
    label: MessageKey,
    /// Whether fleet services are attached.
    available: bool,
    /// The routers the role may read: id and the section's page on it.
    routers: Vec<(String, String)>,
}

localized!(Picker);

/// The picker of `section` for `user` in `shell`, or the 404 page for a section that is not
/// about one router.
// cancel-safe: reads only.
pub(super) async fn page(
    state: &WebState,
    user: &CurrentUser,
    section: Section,
    shell: Shell,
) -> Response {
    let Some(page) = section.router_page() else {
        return errors::response(Kind::NotFound, shell);
    };
    let mut picker = Picker {
        shell: shell.with_section(section),
        label: section.label(),
        available: false,
        routers: Vec::new(),
    };
    let Some(fleet) = state.fleet() else {
        return errors::render(&picker);
    };
    match fleet.visible(user.role()).await {
        Ok(entries) => {
            picker.available = true;
            picker.routers = entries
                .into_iter()
                .map(|entry| {
                    let href = format!("/ui/r/{}/{page}", entry.profile.id);
                    (entry.profile.id, href)
                })
                .collect();
            errors::render(&picker)
        }
        Err(error) => errors::internal(&error, picker.shell),
    }
}
