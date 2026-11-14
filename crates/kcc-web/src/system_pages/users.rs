//! The router accounts at `/ui/r/{router}/system/users`: login names and their service
//! tags in a filterable table, with Add, Edit tags and Delete where the role may manage
//! router accounts.
//!
//! Account changes are management changes (a router account may be the one kcc or a
//! person signs in with): they need `ManageUsers` and `Destructive` and run inside the
//! router's fail-safe timer. The account kcc signs in with cannot be deleted, nor its
//! password changed. Set password opens the write-only password dialog
//! (`secret_pages`); no page shows a password.

use askama::Template;
use axum::{
    Form,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use kcc_catalog::Catalog;
use kcc_domain::{RouterCtx, router_users};
use kcc_i18n::{bundle::MessageKey, keys};

use super::{
    shared::{Visit, profile_login},
    tabs::{Tab, TabBar},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    page::{Localize as _, Shell},
    page_kit::{
        context::fragment_shell,
        gate::Controls,
        request::{rendered, with_query},
    },
    table::{
        Direction, Sort,
        rows::{Row, SortKey, Table, TableQuery},
    },
};

/// The catalog command whose `tag` keyword lists the service tags.
const TAG_COMMAND: &str = "user tag";

/// The page.
#[derive(Template)]
#[template(path = "pages/system_users.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// The system tabs.
    tabs: TabBar,
    /// Router profile id.
    router: String,
    /// Why the accounts could not be read.
    problem: Option<MessageKey>,
    /// The accounts.
    region: Option<Region>,
    /// Whether the role may add accounts.
    add: bool,
}

localized!(Page);

/// The accounts table with its filter and pager; a change sends it again out of band.
#[derive(Template)]
#[template(path = "partials/system_users_region.html")]
pub(crate) struct Region {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The accounts shown.
    table: Table<Account>,
    /// The row actions the role may use.
    actions: RowActions,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Region);

/// The row actions a role may use on the accounts.
#[derive(Debug, Clone, Copy)]
struct RowActions {
    /// Edit tags.
    edit_tags: bool,
    /// Set password (not on the account kcc signs in with).
    set_password: bool,
    /// Delete (not on the account kcc signs in with).
    delete: bool,
}

impl RowActions {
    /// Whether the rows have any action.
    const fn any(self) -> bool {
        self.edit_tags || self.set_password || self.delete
    }
}

/// One router account as the table shows it; its password never leaves the domain.
#[derive(Debug, Clone)]
pub(crate) struct Account {
    /// Login name.
    name: String,
    /// Service tags.
    tags: Vec<String>,
    /// Whether kcc signs in to the router with this account.
    signs_in: bool,
}

impl Row for Account {
    const COLUMNS: &'static [&'static str] = &["name", "tags"];
    const DEFAULT: Sort = Sort::new("name", Direction::Ascending);

    fn key(&self, column: &str) -> SortKey {
        match column {
            "tags" => SortKey::text(&self.tags.join(" ")),
            _ => SortKey::text(&self.name),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.name.to_lowercase().contains(needle)
            || self
                .tags
                .iter()
                .any(|tag| tag.to_lowercase().contains(needle))
    }
}

impl Account {
    /// Login name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The service tags, comma separated.
    pub(crate) fn tag_list(&self) -> String {
        self.tags.join(", ")
    }

    /// The service tags.
    pub(crate) fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Whether the account has no tags.
    pub(crate) const fn untagged(&self) -> bool {
        self.tags.is_empty()
    }

    /// Whether kcc signs in to the router with this account.
    pub(crate) const fn signs_in(&self) -> bool {
        self.signs_in
    }
}

impl Region {
    /// The tag dialog of `account`.
    fn tags_url(&self, account: &Account) -> String {
        with_query(
            &format!("/ui/r/{}/system/users/tags", self.router),
            &[("name", &account.name)],
        )
    }

    /// The delete dialog of `account`.
    fn delete_url(&self, account: &Account) -> String {
        with_query(
            &format!("/ui/r/{}/system/users/delete", self.router),
            &[("name", &account.name)],
        )
    }

    /// The password dialog of `account`.
    fn password_url(&self, account: &Account) -> String {
        with_query(
            &format!("/ui/r/{}/system/users/password", self.router),
            &[("name", &account.name)],
        )
    }
}

/// The accounts of `router` read through `domain`, marked with the login kcc uses.
///
/// # Errors
///
/// Returns the message to show when the router did not answer with its accounts.
// cancel-safe: reads only.
pub(crate) async fn accounts(
    domain: &RouterCtx,
    login: Option<&str>,
) -> Result<Vec<Account>, MessageKey> {
    let users = router_users::read_users(domain).await.map_err(|error| {
        tracing::warn!(%error, "router accounts could not be read");
        keys::WEB_SYSTEM_READ_FAILED
    })?;
    Ok(users
        .into_iter()
        .filter_map(|user| {
            let name = user.name?;
            Some(Account {
                signs_in: login == Some(name.as_str()),
                name,
                tags: user.tags,
            })
        })
        .collect())
}

/// The service tags the router's catalog offers, in catalog order; prefix families such
/// as `rights.` are left out because they are not one tag.
pub(crate) fn offered_tags(catalog: &Catalog) -> Vec<String> {
    catalog
        .lookup(TAG_COMMAND)
        .and_then(|command| command.arguments.get("tag"))
        .map(|argument| {
            argument
                .values
                .iter()
                .filter(|tag| !tag.ends_with('.'))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// Who looks at the accounts of which router, and the table query of the page.
pub(crate) struct Viewer<'call> {
    /// The signed-in user.
    user: &'call CurrentUser,
    /// Router profile id.
    router: &'call str,
    /// Filter, sort and page of the table.
    query: TableQuery,
}

impl<'call> Viewer<'call> {
    /// `user` looking at the accounts of `router` as `query` asks.
    pub(crate) const fn new(
        user: &'call CurrentUser,
        router: &'call str,
        query: TableQuery,
    ) -> Self {
        Self {
            user,
            router,
            query,
        }
    }

    /// What the role may do with the accounts.
    fn controls(&self, catalog: &Catalog) -> Controls {
        Controls::new(self.user.role(), self.router)
            .with_operations(router_users::DESCRIPTOR.write_ops, Some(catalog))
    }

    /// The accounts region for `rows`.
    fn region(&self, rows: Vec<Account>, catalog: &Catalog) -> Region {
        let controls = self.controls(catalog);
        Region {
            shell: fragment_shell(self.user.locale()),
            router: self.router.to_owned(),
            table: Table::new(
                rows,
                &self.query,
                format!("/ui/r/{}/system/users", self.router),
            ),
            actions: RowActions {
                edit_tags: controls.allows("set_tag"),
                set_password: controls.allows("set_password"),
                delete: controls.allows("delete"),
            },
            oob: false,
        }
    }

    /// The accounts region read again through `domain` after a change, out of band.
    // cancel-safe: reads only.
    pub(crate) async fn refreshed(&self, state: &WebState, domain: &RouterCtx) -> Option<String> {
        let login = profile_login(state, self.user, self.router).await;
        let rows = accounts(domain, login.as_deref()).await.ok()?;
        rendered(&Region {
            oob: true,
            ..self.region(rows, &domain.catalog)
        })
    }
}

/// `GET /ui/r/{router}/system/users`: the accounts and the controls the role may use.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
    Form(query): Form<TableQuery>,
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
        tabs: TabBar::new(router.clone(), Tab::Users),
        router: router.clone(),
        problem: None,
        region: None,
        add: false,
    };
    let viewer = Viewer::new(&user, &router, query);
    match reading {
        Ok((facts, domain)) => {
            page.add = viewer.controls(facts.catalog()).allows("create");
            let login = profile_login(&state, &user, &router).await;
            match accounts(&domain, login.as_deref()).await {
                Ok(rows) => page.region = Some(viewer.region(rows, facts.catalog())),
                Err(message) => page.problem = Some(message),
            }
        }
        Err(message) => page.problem = Some(message),
    }
    errors::render(&page)
}
