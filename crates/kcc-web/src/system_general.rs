//! The router's general system settings at `/ui/r/{router}/system/general`: the domain
//! page kit's reference page.
//!
//! It shows the host name, description and domain name, the time zone, the router clock
//! and time synchronization; the host name, the description, the time zone and the time
//! server change through one-field dialogs, and a restart or a factory reset needs the
//! router name typed. It shares the system pages' tabs.
//!
//! Routes (route table: `Read`; every change re-checks its operation's permissions):
//!
//! - `GET /ui/r/{router}/system/general`: the page.
//! - `GET|POST /ui/r/{router}/system/general/{hostname|description|timezone|ntp_server}`:
//!   the edit dialog and the change (`Write`).
//! - `POST /ui/r/{router}/system/general/reboot`: the restart (`Destructive`).
//! - `POST /ui/r/{router}/system/general/reset`: the factory reset (`Destructive`).

mod fields;
mod general;
mod reset;

use askama::Template;
use axum::{
    Form, Router,
    extract::{Path, State},
    http::HeaderMap,
    response::Response,
    routing::{get, post},
};
use kcc_domain::system;
use kcc_i18n::{bundle::MessageKey, keys};

use self::{
    fields::{Field, ValueForm},
    general::{Facts, General},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    nav::Section,
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        change::{Applied, Change},
        confirm::Resubmit,
        context::{self, Caller},
        family::Family,
        gate::Controls,
        request::{Params, missing, rendered},
        respond::Answer,
        submit::{Formless, Invalid, Planned, Submission},
    },
    system_pages::tabs::{Tab, TabBar},
};

/// The restart, audited as `web.system_reboot`.
const REBOOT: Operation = Operation::write(&system::DESCRIPTOR, "reboot", "web.system_reboot");

/// The page and action routes.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route("/ui/r/{router}/system/general", get(page))
        .route("/ui/r/{router}/system/general/reboot", post(reboot))
        .route("/ui/r/{router}/system/general/reset", post(reset::reset))
        .route(
            "/ui/r/{router}/system/general/{field}",
            get(edit_dialog).post(edit),
        )
}

/// The page.
#[derive(Template)]
#[template(path = "pages/system_general.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// The settings, when the router answered.
    facts: Option<Facts>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
    /// Whether the role may restart the router.
    restart: bool,
    /// Whether the role may reset the router to its factory settings.
    reset: bool,
}

localized!(Page);

/// `GET /ui/r/{router}/system/general`: the settings and the controls the role may use.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Section::System, Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let controls = Controls::new(user.role(), &router);
    let mut page = Page {
        shell,
        tabs: TabBar::new(router.clone(), Tab::General),
        restart: false,
        reset: false,
        router: router.clone(),
        facts: None,
        problem: None,
    };
    match target.context(&state).await {
        Ok((facts, domain)) => {
            let allowed =
                controls.with_operations(system::DESCRIPTOR.write_ops, Some(facts.catalog()));
            page.restart = allowed.allows("reboot");
            page.reset = allowed.allows("factory_reset");
            let general = General::read(&domain).await;
            page.facts = Some(Facts::new(user.locale(), router, general).with_controls(allowed));
        }
        Err(error) => page.problem = Some(error.message(Family::Changes)),
    }
    errors::render(&page)
}

/// `GET /ui/r/{router}/system/general/{field}`: the edit dialog with the current value.
///
/// # Errors
///
/// Answers 404 for a setting the page does not edit, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn edit_dialog(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    user: CurrentUser,
) -> Result<Response, Answer> {
    let field = Field::from_slug(&slug).ok_or_else(missing)?;
    let action = field.operation().open(&state, &user, &router).await?;
    let domain = action.context().await?;
    let general = General::read(&domain).await;
    Ok(field
        .dialog(&router, user.locale())
        .with_value("value", field.current(&general))
        .show())
}

/// `POST /ui/r/{router}/system/general/{field}`: validates, plans with the system domain,
/// runs the change and answers with its outcome and the settings read back.
///
/// # Errors
///
/// Answers the dialog with its field error (422) when the value is invalid, and what the
/// kit answers when the router or the permission is missing.
pub(crate) async fn edit(
    State(state): State<WebState>,
    Path((router, slug)): Path<(String, String)>,
    user: CurrentUser,
    Form(form): Form<ValueForm>,
) -> Result<Response, Answer> {
    let field = Field::from_slug(&slug).ok_or_else(missing)?;
    let action = field.operation().open(&state, &user, &router).await?;
    let locale = action.locale();
    let dialog = field
        .dialog(&router, locale)
        .with_value("value", form.value().to_owned());
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/system/general/{slug}"),
        "#page-outcome",
    );
    Ok(
        Submission::new(action, &Params::default(), dialog, resubmit)
            .submit(
                |_params| {
                    field
                        .check(form.value())
                        .map_err(|rule| Invalid::at("value", rule))
                },
                async |value, domain| {
                    let operation = field.plan(domain, &value)?;
                    let request = system::change_request(&operation)?;
                    Ok(Planned::of(&[operation], Change::Request(request)))
                },
                async |domain| {
                    let general = General::read(domain).await;
                    let controls = Controls::new(user.role(), &router)
                        .with_operations(system::DESCRIPTOR.write_ops, Some(&domain.catalog));
                    rendered(
                        &Facts::new(locale, router.clone(), general)
                            .with_controls(controls)
                            .out_of_band(),
                    )
                },
            )
            .await,
    )
}

/// `POST /ui/r/{router}/system/general/reboot`: asks for the router name, then restarts
/// the router through the change workflow.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
pub(crate) async fn reboot(
    State(state): State<WebState>,
    Path(router): Path<String>,
    user: CurrentUser,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let action = REBOOT.open(&state, &user, &router).await?;
    let resubmit = Resubmit::new(
        format!("/ui/r/{router}/system/general/reboot"),
        "#page-outcome",
    );
    Ok(
        Submission::new(action, &Params::of(pairs), Formless, resubmit)
            .submit(
                |_params| Ok(()),
                async |(), _ctx| {
                    Ok(Planned::described(|changes, context| {
                        Box::pin(async move {
                            system::reboot(changes, context)
                                .await
                                .map(|result| Applied::Terminal(result.responses))
                        })
                    }))
                },
                async |_ctx| None,
            )
            .await,
    )
}
