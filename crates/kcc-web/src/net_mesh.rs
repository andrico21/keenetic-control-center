//! The mesh page at `/ui/r/{router}/mesh`.
//!
//! The members of the router's mesh Wi-Fi system with their name, identifier, MAC address
//! and status. Check for updates and Update firmware are ordinary changes. Restart is
//! destructive: it needs the router name typed, then runs the mesh domain's terminal
//! member restart, whose own confirmation is satisfied by the one the user gave here.

use askama::Template;
use axum::{
    Form,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use kcc_app::workflow::WorkflowError;
use kcc_catalog::Risk;
use kcc_domain::{
    ChangeOp, DomainError, RouterCtx,
    mesh::{self, Member, RebootError},
};
use kcc_i18n::{
    bundle::{MessageKey, tr},
    keys,
    locale::Locale,
};
use kcc_rci::ObjectName;

use crate::{
    WebState,
    authz::{CurrentSession, CurrentUser},
    errors,
    net_pages::{Call, Tab, Tabs, Viewer},
    page::{Localize as _, Shell},
    page_kit::{
        action::Operation,
        change::{Applied, Change},
        confirm::Resubmit,
        context,
        context::{Caller, fragment_shell},
        family::Family,
        gate::Controls,
        request::{Params, missing, rendered, with_query},
        respond::{Answer, changed},
        submit::{Formless, Planned, Submission},
    },
};

/// Checking a member for updates, audited as `web.mesh_update_check`.
const CHECK: Operation =
    Operation::write(&mesh::DESCRIPTOR, "update_check", "web.mesh_update_check");

/// Updating a member's firmware, audited as `web.mesh_update_start`.
const UPDATE: Operation =
    Operation::write(&mesh::DESCRIPTOR, "update_start", "web.mesh_update_start");

/// Restarting a member, audited as `web.mesh_reboot`.
const RESTART: Operation = Operation::write(&mesh::DESCRIPTOR, "member_reboot", "web.mesh_reboot");

/// A mesh domain planner of an ordinary member action.
type Planner = fn(&RouterCtx, &str) -> Result<ChangeOp, DomainError>;

/// The page.
#[derive(Template)]
#[template(path = "pages/net_mesh.html")]
struct Page {
    /// Page shell.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The network pages' tab bar.
    tabs: Tabs,
    /// The members, when the router answered.
    listing: Option<Listing>,
    /// Why the router could not be read.
    problem: Option<MessageKey>,
}

localized!(Page);

/// `GET /ui/r/{router}/mesh`: the mesh members and the actions the role may run.
pub(crate) async fn page(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    current: CurrentSession,
    user: CurrentUser,
) -> Response {
    let shell = Caller::new(&headers, &current, &user)
        .shell(&state, Tab::Mesh.section(), Some(&router))
        .await;
    let target = match context::target(&state, &user, &router).await {
        Ok(found) => found,
        Err(refusal) => return refusal.page(shell),
    };
    let mut page = Page {
        shell,
        tabs: Tabs::new(&router, Tab::Mesh),
        router: router.clone(),
        listing: None,
        problem: None,
    };
    match target.context(&state).await {
        Ok((facts, domain)) => {
            let controls = Controls::new(user.role(), &router)
                .with_operations(mesh::DESCRIPTOR.write_ops, Some(facts.catalog()));
            let viewer = Call::new(&state, &user, &router, &headers).viewer(controls);
            match Listing::read(&domain, viewer).await {
                Ok(listing) => page.listing = Some(listing),
                Err(error) => {
                    tracing::warn!(%error, "mesh page: router read failed");
                    page.problem = Some(Family::Changes.unreachable());
                }
            }
        }
        Err(error) => page.problem = Some(error.message(Family::Changes)),
    }
    errors::render(&page)
}

/// The members read back after a change, out of band.
// cancel-safe: reads only.
pub(crate) async fn refreshed(call: Call<'_>, domain: &RouterCtx) -> Option<String> {
    let controls = Controls::new(call.user().role(), call.router())
        .with_operations(mesh::DESCRIPTOR.write_ops, Some(&domain.catalog));
    let listing = Listing::read(domain, call.viewer(controls))
        .await
        .inspect_err(|error| tracing::warn!(%error, "mesh read-back failed"))
        .ok()?;
    rendered(&listing.out_of_band())
}

/// The members; a change sends them again out of band.
#[derive(Template)]
#[template(path = "partials/net_mesh_region.html")]
struct Listing {
    /// Locale carrier.
    shell: Shell,
    /// Router profile id.
    router: String,
    /// The members.
    members: Vec<Member>,
    /// What the role may change.
    controls: Controls,
    /// Whether the region replaces the page's out of band.
    oob: bool,
}

localized!(Listing);

impl Listing {
    /// Reads the members of the router of `domain`.
    ///
    /// # Errors
    ///
    /// Returns the router's error.
    // cancel-safe: reads only.
    async fn read(domain: &RouterCtx, viewer: Viewer) -> Result<Self, DomainError> {
        let members = mesh::read_members(domain).await?;
        let (router, locale, controls) = viewer.into_parts();
        Ok(Self {
            shell: fragment_shell(locale),
            router,
            members,
            controls,
            oob: false,
        })
    }

    /// The region as an out-of-band replacement of the page's.
    const fn out_of_band(mut self) -> Self {
        self.oob = true;
        self
    }

    /// The status of `member`: its status-pill value and its text in the reader's
    /// language.
    fn status(&self, member: &Member) -> Status {
        let (value, key) = match member.online {
            Some(true) => ("online", keys::WEB_ROUTER_ONLINE),
            Some(false) => ("offline", keys::WEB_ROUTER_OFFLINE),
            None => ("unknown", keys::WEB_ROUTER_UNKNOWN),
        };
        Status {
            value,
            text: tr(self.shell.locale(), key, None),
        }
    }

    /// The member actions the role may run on `member`.
    fn actions(&self, member: &Member) -> Vec<MemberAction> {
        let Some(id) = member.id.as_deref() else {
            return Vec::new();
        };
        [
            ("update_check", "check", keys::WEB_MESH_CHECK, false),
            ("update_start", "update", keys::WEB_MESH_UPDATE, false),
            ("member_reboot", "restart", keys::WEB_MESH_RESTART, true),
        ]
        .into_iter()
        .filter(|(operation, _, _, _)| self.controls.allows(operation))
        .map(|(_, action, label, destructive)| MemberAction {
            href: with_query(
                &format!("/ui/r/{}/mesh/action", self.router),
                &[("name", id), ("do", action)],
            ),
            label: tr(self.shell.locale(), label, None),
            destructive,
        })
        .collect()
    }
}

/// The status of a member.
struct Status {
    /// The status-pill value.
    value: &'static str,
    /// The localized text.
    text: String,
}

/// One action on a member.
struct MemberAction {
    /// Where it posts.
    href: String,
    /// The localized label.
    label: String,
    /// Whether it is destructive, which asks for the router name.
    destructive: bool,
}

/// `POST /ui/r/{router}/mesh/action?name=&do=check|update|restart`: a member action.
///
/// # Errors
///
/// Answers 404 for a missing member name or action, and what the kit answers when the
/// router or the permission is missing.
pub(crate) async fn action(
    State(state): State<WebState>,
    Path(router): Path<String>,
    headers: HeaderMap,
    user: CurrentUser,
    Query(query): Query<Vec<(String, String)>>,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let params = Params::new(query, form);
    let member = params.object("name")?;
    let call = Call::new(&state, &user, &router, &headers).on(Tab::Mesh);
    let (operation, plan): (Operation, Planner) = match params.get("do") {
        Some("check") => (CHECK, mesh::plan_update_check),
        Some("update") => (UPDATE, mesh::plan_update_start),
        Some("restart") => return restart(call, &member, &params).await,
        Some(_) | None => return Err(missing()),
    };
    let action = operation.open(&state, &user, &router).await?;
    Ok(Submission::new(action, &params, Formless)
        .submit(
            |_params| Ok(()),
            async |(), domain| {
                let planned = plan(domain, member.as_str())?;
                let request = mesh::change_request(&planned)?;
                Ok(Planned::of(&[planned], Change::Cli(request)))
            },
            async |domain| refreshed(call, domain).await,
        )
        .await)
}

/// Restarts `member` once the router name was typed.
///
/// # Errors
///
/// Answers what the kit answers when the router or the permission is missing.
// NOT cancel-safe: see `Action::run_with`.
async fn restart(call: Call<'_>, member: &ObjectName, params: &Params) -> Result<Response, Answer> {
    let action = RESTART
        .open(call.state(), call.user(), call.router())
        .await?;
    let resubmit = Resubmit::new(
        with_query(
            &format!("/ui/r/{}/mesh/action", call.router()),
            &[("name", member.as_str()), ("do", "restart")],
        ),
        "#page-outcome",
    );
    if let Some(prompt) = action.confirm(Risk::Destructive, &params.confirmation(), resubmit) {
        return Ok(prompt);
    }
    let locale: Locale = action.locale();
    let id = member.as_str();
    let outcome = action
        .run_with(Risk::Destructive, async |changes, domain| {
            mesh::reboot_member(changes, domain, id, id)
                .await
                .map(|result| Applied::Terminal(result.responses))
                .map_err(workflow_error)
        })
        .await;
    Ok(changed(outcome, None, None, locale))
}

/// The change-workflow error of a member restart that failed.
fn workflow_error(error: RebootError) -> WorkflowError {
    match error {
        RebootError::Workflow(inner) => inner,
        RebootError::Domain(DomainError::Validation { issues }) => {
            WorkflowError::CatalogValidation { issues }
        }
        RebootError::Domain(DomainError::Rci(inner)) => WorkflowError::Rci(inner),
        RebootError::Domain(_) | RebootError::ConfirmationMismatch | _ => {
            WorkflowError::InvalidResponse
        }
    }
}
