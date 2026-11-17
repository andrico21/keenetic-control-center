//! KeenDNS at `/ui/r/{router}/system/keendns`: the router's KeenDNS name and its state,
//! with Book and Release, the remote access level, and web proxy entries that publish a
//! home device under the name.
//!
//! Booking and releasing are writes; releasing the name kcc reaches the router by is a
//! management change. The access level and proxy entries change how the router and the
//! home network are reached from outside: they are management changes too. A management
//! change needs the change's own `Write`, asks first and runs inside the fail-safe timer.

use askama::Template;
use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_domain::{RouterCtx, keendns};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    shared::Visit,
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    markup::Rendered,
    page::{Localize as _, Shell},
    page_kit::{context::fragment_shell, gate::Controls, request::rendered},
};

/// The page.
#[derive(Template)]
#[template(path = "pages/system_keendns.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why KeenDNS could not be read.
    problem: Option<MessageKey>,
    /// The name and its state.
    status: Option<StatusPanel>,
    /// What the role may change.
    controls: Controls,
}

localized!(Page);

/// The name panel; a change sends it again out of band.
#[derive(Template)]
#[template(path = "partials/system_keendns_status.html")]
pub(crate) struct StatusPanel {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The booked full name.
    name: Option<String>,
    /// The registration state as the router reports it.
    state: Option<String>,
    /// Whether a name is booked.
    booked: bool,
    /// The name action the role may take.
    offer: Offer,
    /// Whether the panel replaces the page's out of band.
    oob: bool,
}

/// The name action the panel offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Offer {
    /// Nothing the role may do.
    Nothing,
    /// Book a name.
    Book,
    /// Release the booked name.
    Release,
}

localized!(StatusPanel);
fragment!(StatusPanel);

/// What the role may change on the KeenDNS page of `router`.
pub(crate) fn controls(user: &CurrentUser, router: &str, domain: &RouterCtx) -> Controls {
    Controls::new(user.role(), router)
        .with_operations(keendns::DESCRIPTOR.write_ops, Some(&domain.catalog))
}

impl StatusPanel {
    /// The booked full name.
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The registration state.
    fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// Whether the panel offers Book.
    fn books(&self) -> bool {
        self.offer == Offer::Book
    }

    /// Whether the panel offers Release.
    fn releases(&self) -> bool {
        self.offer == Offer::Release
    }
}

/// Who looks at the KeenDNS page of which router.
pub(crate) struct Viewer<'call> {
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
}

impl<'call> Viewer<'call> {
    /// `user` looking at the KeenDNS page of `router`.
    pub(crate) const fn new(user: &'call CurrentUser, router: &'call str) -> Self {
        Self { user, router }
    }

    /// The name panel read through `domain`.
    ///
    /// # Errors
    ///
    /// Returns the message to show when the router did not answer.
    // cancel-safe: reads only.
    async fn panel(&self, domain: &RouterCtx) -> Result<StatusPanel, MessageKey> {
        let found = keendns::read_status(domain).await.map_err(|error| {
            tracing::warn!(%error, "KeenDNS could not be read");
            keys::WEB_SYSTEM_READ_FAILED
        })?;
        let allowed = controls(self.user, self.router, domain);
        let booked = found.booked.unwrap_or(false);
        Ok(StatusPanel {
            shell: fragment_shell(self.user.locale()),
            router: self.router.to_owned(),
            name: found.name.filter(|name| !name.is_empty()),
            state: found.status,
            booked,
            offer: if booked && allowed.allows("drop_name") {
                Offer::Release
            } else if !booked && allowed.allows("book_name") {
                Offer::Book
            } else {
                Offer::Nothing
            },
            oob: false,
        })
    }

    /// The name panel read again through `domain` after a change, out of band.
    // cancel-safe: reads only.
    pub(crate) async fn refreshed(&self, domain: &RouterCtx) -> Option<Rendered> {
        let panel = self.panel(domain).await.ok()?;
        rendered(&StatusPanel { oob: true, ..panel })
    }
}

/// `GET /ui/r/{router}/system/keendns`: the name, remote access and proxy entries.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let (shell, reading) = match Visit::new(&headers, &current, &user)
        .open(&state, &router)
        .await
    {
        Ok(opened) => opened,
        Err(refusal) => return refusal.into_response(),
    };
    let mut page = Page {
        shell,
        tabs: TabBar::new(router.clone(), Tab::KeenDns),
        router: router.clone(),
        problem: None,
        status: None,
        controls: Controls::default(),
    };
    match reading {
        Ok((_, domain)) => {
            page.controls = controls(&user, &router, &domain);
            match Viewer::new(&user, &router).panel(&domain).await {
                Ok(panel) => page.status = Some(panel),
                Err(message) => page.problem = Some(message),
            }
        }
        Err(message) => page.problem = Some(message),
    }
    errors::render(&page)
}
