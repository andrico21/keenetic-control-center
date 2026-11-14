//! Page handlers: the router pickers of the sections and the redirects into `/ui/`.
//!
//! A section about one router (clients aside, which has its own landing page) answers at
//! `/ui/<section>` with its router picker; the navigation links there only when the page
//! shows no router and the role may read several. The dashboard section is the fleet
//! overview (`overview`).

mod picker;

use axum::{
    extract::{Path, State, rejection::PathRejection},
    http::HeaderMap,
    response::{Redirect, Response},
};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors::{self, Kind},
    nav::Section,
    overview::masthead,
    prefs,
};

/// `GET /` and `GET /ui`: redirect to the dashboard.
pub(crate) async fn to_ui() -> Redirect {
    Redirect::to(Section::Dashboard.href())
}

/// `GET /ui/{*rest}`: the router picker of a section about one router, or the 404 page for
/// any other path.
pub(crate) async fn section(
    State(state): State<WebState>,
    rest: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = prefs::shell_for_locale(&headers, user.locale())
        .with_csrf_token(current.session().csrf_token().to_owned())
        .with_fleet(masthead(&state, user.role(), None).await, None);
    match rest.ok().and_then(|Path(slug)| Section::from_slug(&slug)) {
        Some(section) => picker::page(&state, &user, section, shell).await,
        None => errors::response(Kind::NotFound, shell),
    }
}

/// Any method but `GET` under `/ui/{*rest}`: the 404 page.
pub(crate) async fn not_found(
    State(state): State<WebState>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    errors::response(
        Kind::NotFound,
        prefs::shell_for_locale(&headers, user.locale())
            .with_csrf_token(current.session().csrf_token().to_owned())
            .with_fleet(masthead(&state, user.role(), None).await, None),
    )
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;

    use askama::Template;
    use fluent_bundle::FluentArgs;
    use kcc_i18n::{bundle::tr, keys, locale::Locale};

    use crate::{
        nav::Section,
        page::{FleetEntry, Localize as _, RouterStatus, Shell, Theme},
        table::{Direction, Sort},
    };

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// A page with nothing in it but the shell.
    #[derive(Template)]
    #[template(
        ext = "html",
        source = r#"{% extends "base.html" %}{% block title %}{% endblock %}{% block content %}{% endblock %}"#
    )]
    struct ShellOnly {
        /// The shell under test.
        shell: Shell,
    }

    localized!(ShellOnly);

    /// Every component macro with fixed sample data.
    #[derive(Template)]
    #[template(
        ext = "html",
        source = r#"{%- import "components.html" as ui -%}
{{ ui::field("user", "username", t(keys::WEB_LOGIN_USERNAME), "admin", "") }}
{{ ui::field("pass", "password", t(keys::WEB_LOGIN_PASSWORD), "", t(keys::ERRORS_AUTH_FAILED), "password", "current-password") }}
{{ ui::field("note", "note", t(keys::COMMON_EDIT), hostile, "") }}
<table class="table"><thead><tr>{{ ui::sort_header(t(keys::DOMAINS_MODEL), sort.header("/ui/clients", "model")) }}{{ ui::sort_header(t(keys::DOMAINS_SERIAL), sort.header("/ui/clients", "serial")) }}</tr></thead></table>
{% call ui::dialog_body(t(keys::WEB_CONFIRM_DESTRUCTIVE)) %}<p>{{ t(keys::COMMON_DELETE) }}</p>{% endcall %}
{{ ui::toast("success", t(keys::MIGRATE_DONE)) }}"#
    )]
    struct Gallery {
        /// Shell providing the locale.
        shell: Shell,
        /// Sort order of the sample table.
        sort: Sort,
        /// A value that must come out escaped.
        hostile: &'static str,
    }

    localized!(Gallery);

    #[test]
    fn components_render_accessible_markup() -> TestResult {
        let html = Gallery {
            shell: Shell::new(Locale::En, Theme::System),
            sort: Sort::new("model", Direction::Descending),
            hostile: "\"><script>alert(1)</script>",
        }
        .render()?;
        for expected in [
            "<label class=\"field__label\" for=\"user\">Username</label>",
            "id=\"user\" name=\"username\" type=\"text\" value=\"admin\" autocomplete=\"off\">",
            "type=\"password\" value=\"\" autocomplete=\"current-password\" aria-invalid=\"true\" aria-describedby=\"pass-error\">",
            "<p class=\"field__error\" id=\"pass-error\">Invalid username or password.</p>",
            "<th scope=\"col\" aria-sort=\"descending\"><a class=\"sort\" href=\"/ui/clients?sort=model&#38;dir=asc\">Model</a></th>",
            "<th scope=\"col\" aria-sort=\"none\"><a class=\"sort\" href=\"/ui/clients?sort=serial&#38;dir=asc\">Serial number</a></th>",
            "<h2 class=\"dialog__title\" id=\"dialog-title\">This action cannot be undone. Continue?</h2>",
            "<form method=\"dialog\"><button class=\"button button--ghost\" type=\"submit\">Close</button></form>",
            "<div class=\"dialog__body\"><p>Delete</p></div>",
            "<div class=\"toast\" data-tone=\"success\">",
            "<p class=\"toast__message\">Migration finished.</p>",
            "data-kcc-toast-close>Close</button>",
        ] {
            assert!(html.contains(expected), "missing {expected} in {html}");
        }
        assert_eq!(
            html.matches("aria-invalid").count(),
            1,
            "only the field with an error is invalid"
        );
        assert!(!html.contains("<script>"), "values are escaped: {html}");
        assert!(html.contains("&#60;script&#62;"), "escaped hostile value");
        Ok(())
    }

    #[test]
    fn the_shell_renders_fleet_status_badge_and_csrf_slot() -> TestResult {
        let shell = Shell::new(Locale::Ru, Theme::Light)
            .with_section(Section::Wifi)
            .with_csrf_token("token-123".to_owned())
            .with_fleet(
                vec![
                    FleetEntry::new("home".to_owned(), "Home <router>".to_owned(), true),
                    FleetEntry::new("cottage".to_owned(), "Cottage".to_owned(), false),
                ],
                Some(RouterStatus::Offline),
            )
            .with_unsaved_changes(3);
        let html = ShellOnly { shell }.render()?;
        let mut args = FluentArgs::new();
        args.set("count", 3_u32);
        let badge = tr(Locale::Ru, keys::WEB_UNSAVED_CHANGES, Some(&args));
        for expected in [
            "<html lang=\"ru\" dir=\"ltr\" class=\"theme-light\">".to_owned(),
            "<meta name=\"csrf-token\" content=\"token-123\">".to_owned(),
            "<option value=\"home\" selected>Home &#60;router&#62;</option>".to_owned(),
            "<option value=\"cottage\">Cottage</option>".to_owned(),
            format!(
                "<span class=\"status\" data-status=\"offline\">{}</span>",
                tr(Locale::Ru, keys::WEB_ROUTER_OFFLINE, None)
            ),
            format!("<a class=\"badge\" href=\"/ui/configuration\">{badge}</a>"),
            "href=\"/ui/r/home/wifi\" aria-current=\"page\"".to_owned(),
        ] {
            assert!(html.contains(&expected), "missing {expected}");
        }
        assert!(
            !html.contains(&tr(Locale::Ru, keys::WEB_FLEET_EMPTY, None)),
            "no empty-fleet note when routers exist"
        );
        Ok(())
    }

    #[test]
    fn an_empty_shell_shows_the_no_router_note_only() -> TestResult {
        let html = ShellOnly {
            shell: Shell::new(Locale::En, Theme::System).with_section(Section::Dashboard),
        }
        .render()?;
        assert!(html.contains("No routers configured"), "empty fleet note");
        for absent in [
            "<select",
            "data-status=",
            "class=\"badge\"",
            "csrf-token",
            "class=\"theme-",
        ] {
            assert!(!html.contains(absent), "unexpected {absent}");
        }
        Ok(())
    }
}
