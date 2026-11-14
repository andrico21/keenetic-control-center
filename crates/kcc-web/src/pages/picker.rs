//! The router picker of a section about one router: the routers the role may read, each
//! with a link to the section's page on it.

use askama::Template;
use axum::response::Response;
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
};

use crate::{
    WebState,
    authz::CurrentUser,
    errors::{self, Kind},
    nav::Section,
    page::{Localize as _, Shell},
    table::{cells::Cell, fleet::routers_table, piece::Piece, view::TableView},
};

/// The picker page.
#[derive(Template)]
#[template(path = "pages/navpicker.html")]
struct Picker {
    /// Page shell, its section marked current.
    shell: Shell,
    /// The section's name, the page title.
    label: MessageKey,
    /// The routers the role may read, each with the section's page on it.
    table: TableView,
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
    let shown = shell.with_section(section);
    let label = section.label();
    let locale = shown.locale();
    let picker = |routers: Option<Vec<String>>| {
        let rows = routers.map(|ids| {
            ids.into_iter()
                .map(|router| {
                    let href = format!("/ui/r/{router}/{page}");
                    let link = Piece::link(href, tr(locale, label, None));
                    (router, Cell::of(vec![link]))
                })
                .collect()
        });
        routers_table((locale, keys::WEB_CLIENTS_LANDING_PAGES), rows)
    };
    let Some(fleet) = state.fleet() else {
        let table = picker(None);
        return errors::render(&Picker {
            shell: shown,
            label,
            table,
        });
    };
    match fleet.visible(user.role()).await {
        Ok(entries) => {
            let table = picker(Some(
                entries.into_iter().map(|entry| entry.profile.id).collect(),
            ));
            errors::render(&Picker {
                shell: shown,
                label,
                table,
            })
        }
        Err(error) => errors::internal(&error, shown),
    }
}
