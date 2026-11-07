//! The connection policies view: one filtered, sorted table of policies with their
//! interfaces in order and multipath, and the row actions the role may use.

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{IntoResponse as _, Response},
};
use fluent_bundle::FluentArgs;
use kcc_domain::{RouterCtx, policies::descriptor::DESCRIPTOR};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};

use super::{
    frame::{Frame, Tab, Visit},
    policy_rows::{Permit, Policy, read_policies},
};
use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    clients_pages::rendered,
    page::{Localize, Shell},
    page_kit::{context::fragment_shell, gate::Controls},
    system_pages::shared::with_query,
    table::rows::{Table, TableQuery},
};

/// The policies table (`partials/routing_policies.html`).
#[derive(Template)]
#[template(path = "partials/routing_policies.html")]
pub(crate) struct PoliciesRegion {
    /// Locale carrier.
    shell: Shell,
    /// Whether the region replaces the page's region out of band.
    oob: bool,
    /// Router profile id.
    router: String,
    /// The shown page of policies.
    table: Table<Policy>,
    /// What the role may change.
    controls: Controls,
}

impl Localize for PoliciesRegion {
    fn shell(&self) -> &Shell {
        &self.shell
    }
}

impl PoliciesRegion {
    /// The region for an out-of-band swap.
    pub(crate) const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The address of the policy action `action` on `policy`, with `extra` parameters.
    fn url(&self, action: &str, policy: &Policy, extra: &[(&str, &str)]) -> String {
        let mut pairs = vec![("name", policy.name())];
        pairs.extend_from_slice(extra);
        with_query(
            &format!("/ui/r/{}/routing/policy/{action}", self.router),
            &pairs,
        )
    }

    /// The address of the dialog of `action` (`description`, `permit`, `delete`) on
    /// `policy`.
    fn action_url(&self, action: &str, policy: &Policy) -> String {
        self.url(action, policy, &[])
    }

    /// The address that takes `permit` off `policy`.
    fn unpermit_url(&self, policy: &Policy, permit: &Permit) -> String {
        self.url("unpermit", policy, &[("interface", permit.interface())])
    }

    /// The address that turns multipath of `policy` on or off.
    fn multipath_url(&self, policy: &Policy) -> String {
        let value = if policy.multipath() { "off" } else { "on" };
        self.url("multipath", policy, &[("value", value)])
    }

    /// The label of `permit`: the interface, with its order when set.
    fn permit_label(&self, permit: &Permit) -> String {
        permit.order().map_or_else(
            || permit.interface().to_owned(),
            |order| {
                let mut args = FluentArgs::new();
                args.set("name", permit.interface().to_owned());
                args.set("value", order.to_string());
                tr(
                    self.shell.locale(),
                    keys::WEB_ROUTING_POLICY_ORDER,
                    Some(&args),
                )
            },
        )
    }

    /// Whether the role may use any row action.
    fn editable(&self) -> bool {
        ["policy", "description", "permit", "multipath"]
            .into_iter()
            .any(|name| self.controls.allows(name))
    }
}

/// `GET /ui/r/{router}/routing/policies`: the connection policies.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    Query(query): Query<TableQuery>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let visit = Visit::new(&headers, &current, &user);
    let (shell, reading) = match visit.open(&state, &router, Tab::Policies).await {
        Ok(found) => found,
        Err(answer) => return answer.into_response(),
    };
    let locale = shell.locale();
    let mut frame = Frame::new(shell, &router, Tab::Policies);
    let region = match reading {
        Ok((facts, domain)) => {
            let controls = Controls::new(user.role(), &router)
                .with_operations(DESCRIPTOR.write_ops, Some(facts.catalog()));
            if controls.allows("policy") {
                let href = format!("/ui/r/{router}/routing/policy/new");
                frame = frame.with_add(href, keys::WEB_ROUTING_POLICY_ADD);
            }
            policies_region(&domain, (&router, &query), (controls, locale))
                .await
                .map(|region| rendered(&region))
        }
        Err(problem) => Err(problem),
    };
    frame.show(region)
}

/// The policies region on `router` for `query`, with the row actions `controls` allow,
/// in `locale`.
///
/// # Errors
///
/// Returns why the router did not answer.
// cancel-safe: reads only.
pub(crate) async fn policies_region(
    domain: &RouterCtx,
    (router, query): (&str, &TableQuery),
    (controls, locale): (Controls, Locale),
) -> Result<PoliciesRegion, MessageKey> {
    let policies = read_policies(domain).await?;
    Ok(PoliciesRegion {
        shell: fragment_shell(locale),
        oob: false,
        router: router.to_owned(),
        table: Table::new(policies, query, format!("/ui/r/{router}/routing/policies")),
        controls,
    })
}
