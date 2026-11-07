//! What the routing, port forwarding and firewall pages share.
//!
//! The family's tabs, the page frame around one view's region, opening a view on its
//! router, the router's interface names and the workflow error of a failed domain call.

use askama::Template;
use axum::{http::HeaderMap, response::Response};
use kcc_app::workflow::WorkflowError;
use kcc_domain::{DomainError, RouterCtx, interfaces};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    clients_pages::TabLink,
    errors,
    nav::Section,
    page::{Localize, Shell},
    page_kit::{
        context::{self, Caller},
        family::Family,
        respond::Answer,
    },
    system_pages::shared::Reading,
};

/// One page of the routing and firewall family, for the tabs above each page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tab {
    /// Static routes.
    Routes,
    /// The routing table.
    Table,
    /// Connection policies.
    Policies,
    /// Port forwarding.
    Nat,
    /// The firewall.
    Firewall,
}

impl Tab {
    /// Every tab, in order.
    const ALL: [Self; 5] = [
        Self::Routes,
        Self::Table,
        Self::Policies,
        Self::Nat,
        Self::Firewall,
    ];

    /// The tab's page on `router`.
    pub(crate) fn href(self, router: &str) -> String {
        let tail = match self {
            Self::Routes => "routing",
            Self::Table => "routing/table",
            Self::Policies => "routing/policies",
            Self::Nat => "nat",
            Self::Firewall => "firewall",
        };
        format!("/ui/r/{router}/{tail}")
    }

    /// The tab's label, also its page title.
    pub(crate) const fn label(self) -> MessageKey {
        match self {
            Self::Routes => keys::WEB_ROUTING_STATIC_TITLE,
            Self::Table => keys::WEB_ROUTING_TABLE_TITLE,
            Self::Policies => keys::WEB_ROUTING_POLICIES_TITLE,
            Self::Nat => keys::WEB_NAT_TITLE,
            Self::Firewall => keys::WEB_FIREWALL_TITLE,
        }
    }

    /// The navigation section the tab belongs to.
    const fn section(self) -> Section {
        match self {
            Self::Routes | Self::Table | Self::Policies => Section::Routing,
            Self::Nat | Self::Firewall => Section::Firewall,
        }
    }

    /// The family's tabs on `router`, `self` marked current.
    fn links(self, router: &str) -> Vec<TabLink> {
        Self::ALL
            .into_iter()
            .map(|tab| TabLink::new(tab.href(router), tab.label(), tab == self))
            .collect()
    }
}

/// Who opens a view: the request headers, the session and the signed-in user.
#[derive(Clone, Copy)]
pub(crate) struct Visit<'request> {
    /// Request headers, for the theme cookie.
    headers: &'request HeaderMap,
    /// Session, for the CSRF token.
    current: &'request CurrentSession,
    /// Signed-in user.
    user: &'request CurrentUser,
}

impl<'request> Visit<'request> {
    /// The visit of one request.
    pub(crate) const fn new(
        headers: &'request HeaderMap,
        current: &'request CurrentSession,
        user: &'request CurrentUser,
    ) -> Self {
        Self {
            headers,
            current,
            user,
        }
    }

    /// The signed-in user.
    pub(crate) const fn user(self) -> &'request CurrentUser {
        self.user
    }

    /// Opens the page of `tab` on `router`: the shell with the tab's section current and
    /// the router selected, then the router's facts and domain context.
    ///
    /// # Errors
    ///
    /// The error page when the router is unknown, outside the role's scope or the fleet
    /// is not configured.
    // cancel-safe: reads only.
    pub(crate) async fn open(
        self,
        state: &WebState,
        router: &str,
        tab: Tab,
    ) -> Result<(Shell, Reading), Answer> {
        let shell = Caller::new(self.headers, self.current, self.user)
            .shell(state, tab.section(), Some(router))
            .await;
        let target = match context::target(state, self.user, router).await {
            Ok(found) => found,
            Err(refusal) => return Err(refusal.page(shell).into()),
        };
        let reading = target
            .context(state)
            .await
            .map_err(|error| error.message(Family::Changes));
        Ok((shell, reading))
    }
}

/// One page of the family: the tabs, the head with the view's primary action, the view
/// switch, the outcome region and the view's region (`pages/routing.html`).
#[derive(Template)]
#[template(path = "pages/routing.html")]
pub(crate) struct Frame {
    /// Page shell.
    shell: Shell,
    /// The page title.
    title: MessageKey,
    /// Router profile id.
    router: String,
    /// The family's tabs.
    tabs: Vec<TabLink>,
    /// The page's views, such as IPv4 and IPv6; empty for none.
    views: Vec<TabLink>,
    /// The accessible name of the view switch.
    views_label: MessageKey,
    /// The view's primary action: the dialog it opens and its label.
    add: Option<(String, MessageKey)>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
    /// The view's region, rendered.
    region: Option<String>,
}

impl Localize for Frame {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl Frame {
    /// The page of `tab` on `router`, titled by the tab.
    pub(crate) fn new(shell: Shell, router: &str, tab: Tab) -> Self {
        Self {
            shell,
            title: tab.label(),
            router: router.to_owned(),
            tabs: tab.links(router),
            views: Vec::new(),
            views_label: keys::WEB_ROUTING_FAMILY,
            add: None,
            problem: None,
            region: None,
        }
    }

    /// Adds the view switch `views`, named `label`.
    pub(crate) fn with_views(mut self, label: MessageKey, views: Vec<TabLink>) -> Self {
        self.views_label = label;
        self.views = views;
        self
    }

    /// Adds the primary action: the dialog at `href`, labelled `label`.
    pub(crate) fn with_add(mut self, href: String, label: MessageKey) -> Self {
        self.add = Some((href, label));
        self
    }

    /// The page with the view's `region`, or why the router could not be read.
    pub(crate) fn show(mut self, region: Result<Option<String>, MessageKey>) -> Response {
        match region {
            Ok(shown) => self.region = shown,
            Err(problem) => self.problem = Some(problem),
        }
        errors::render(&self)
    }
}

/// A view switch link: `href`, labelled `label`, current when `current`.
pub(crate) const fn view(href: String, label: MessageKey, current: bool) -> TabLink {
    TabLink::new(href, label, current)
}

/// The change-workflow error a domain read or plan failed with inside a change.
pub(crate) fn workflow_error(error: DomainError) -> WorkflowError {
    match error {
        DomainError::Workflow(workflow) => workflow,
        DomainError::Rci(rci) => WorkflowError::Rci(rci),
        DomainError::Validation { issues } => WorkflowError::CatalogValidation { issues },
        DomainError::PermissionDenied => WorkflowError::PermissionDenied {
            router: String::new(),
        },
        DomainError::InvalidResponse | _ => WorkflowError::InvalidResponse,
    }
}

/// The IP protocol `name` a router table reports, as the rules tables show it; the
/// router's word when the pages do not know it.
pub(crate) fn protocol_text(locale: Locale, name: &str) -> String {
    let key = match name.to_ascii_lowercase().as_str() {
        "tcp" => keys::WEB_ROUTING_PROTOCOL_TCP,
        "udp" => keys::WEB_ROUTING_PROTOCOL_UDP,
        "icmp" => keys::WEB_ROUTING_PROTOCOL_ICMP,
        "esp" => keys::WEB_ROUTING_PROTOCOL_ESP,
        "gre" => keys::WEB_ROUTING_PROTOCOL_GRE,
        "ipip" => keys::WEB_ROUTING_PROTOCOL_IPIP,
        _ => return name.to_owned(),
    };
    tr(locale, key, None)
}

/// The names of the router's interfaces, sorted; none when the router does not say.
// cancel-safe: reads only.
pub(crate) async fn interface_names(domain: &RouterCtx) -> Vec<String> {
    interfaces::read_interfaces(domain).await.map_or_else(
        |error| {
            tracing::warn!(%error, "routing page: interfaces unavailable");
            Vec::new()
        },
        |found| found.into_keys().collect(),
    )
}
