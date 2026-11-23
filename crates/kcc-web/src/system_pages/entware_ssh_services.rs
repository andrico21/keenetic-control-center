//! The service actions of the SSH section.
//!
//! The list, a service's status and its log are reads, bounded by the page's read limit;
//! start, stop and restart run as write jobs that read the service's state back.

use axum::{
    Form,
    extract::{Path, RawQuery, State},
    response::Response,
};
use fluent_bundle::FluentArgs;
use kcc_domain::entware::{
    service_log::service_log,
    ssh::ops::{self, ServiceVerb, job::Mutation},
};
use kcc_i18n::{bundle::tr, keys};
use kcc_ssh::{grammar::ServiceName, parse::ServiceState};

use super::{
    entware_ssh_desk::{Desk, Doing},
    entware_ssh_ops::{again, started},
    entware_ssh_views::{LogView, ServicesView},
    shared::{merged, value},
};
use crate::{
    WebState,
    authz::CurrentUser,
    page_kit::{
        outcome::{Failure, Outcome},
        request::missing,
        respond::{Answer, close_dialog},
    },
};

/// Log records a service's log view shows at most.
const LOG_LINES: u32 = 100;

/// A service action.
#[derive(Clone, Copy)]
enum ServiceOp {
    /// The services.
    List,
    /// One service's state.
    Status,
    /// One service's log.
    Log,
    /// Starts, stops or restarts one service.
    Act(ServiceVerb),
}

impl ServiceOp {
    /// The action named `word`, and its audit id.
    fn parse(word: &str) -> Option<(Self, &'static str)> {
        Some(match word {
            "list" => (Self::List, "web.entware_ssh_services_list"),
            "status" => (Self::Status, "web.entware_ssh_service_status"),
            "log" => (Self::Log, "web.entware_ssh_service_log"),
            "start" => (
                Self::Act(ServiceVerb::Start),
                "web.entware_ssh_service_start",
            ),
            "stop" => (Self::Act(ServiceVerb::Stop), "web.entware_ssh_service_stop"),
            "restart" => (
                Self::Act(ServiceVerb::Restart),
                "web.entware_ssh_service_restart",
            ),
            _ => return None,
        })
    }
}

/// `POST .../entware/ssh/services/{op}`: `list`, and `status`, `log`, `start`, `stop` or
/// `restart` with `name`.
///
/// # Errors
///
/// What the desk answers, and 404 for another action.
// NOT cancel-safe: a change job may be started, and its audit entry queued, before the future
// is dropped.
pub(crate) async fn services(
    State(state): State<WebState>,
    Path((router, op)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    user: CurrentUser,
    Form(form): Form<Vec<(String, String)>>,
) -> Result<Response, Answer> {
    let (action, audited) = ServiceOp::parse(&op).ok_or_else(missing)?;
    let desk = Desk::open(&state, &user, &router, audited).await?;
    let pairs = merged(query.as_deref(), form);
    let typed = value(&pairs, "name").unwrap_or_default();
    let named = match action {
        ServiceOp::List => None,
        ServiceOp::Status | ServiceOp::Log | ServiceOp::Act(_) => {
            let Ok(name) = ServiceName::parse(typed) else {
                let rule = tr(
                    desk.locale(),
                    keys::WEB_SYSTEM_ENTWARE_SSH_SERVICE_RULE,
                    None,
                );
                return Ok(desk.refuse(Failure::new(rule, "validation_failed")).await);
            };
            Some(name)
        }
    };
    let (target, doing) = match action {
        ServiceOp::List | ServiceOp::Log => ("#entware-ssh-services", Doing::Read),
        ServiceOp::Status => ("#page-outcome", Doing::Read),
        ServiceOp::Act(_) => ("#page-outcome", Doing::Change),
    };
    if let Some(prompt) = desk.ask(
        &pairs,
        again(&router, ("services", &op), typed, target),
        doing,
    ) {
        return Ok(prompt);
    }
    let domain = desk.context().await?;
    let (services, caller) = (desk.services(), desk.caller());
    Ok(match (action, named) {
        (ServiceOp::List, _) => {
            let found = desk
                .read(ops::services_list(services, &domain, &caller))
                .await?;
            close_dialog(ServicesView::new(desk.locale(), &found).answer())
        }
        (ServiceOp::Status, Some(name)) => {
            let shown = name.as_str().to_owned();
            let read = ops::service_status(services, &domain, &caller, name);
            let running = desk.read(read).await?;
            let said = said_state(&desk, &shown, running);
            desk.answer(Outcome::info(said, "success"), None, None)
        }
        (ServiceOp::Log, Some(name)) => {
            let shown = name.as_str().to_owned();
            let records = desk
                .read(service_log(&domain, &caller, name, LOG_LINES))
                .await?;
            close_dialog(LogView::new(desk.locale(), &shown, &records).answer())
        }
        (ServiceOp::Act(verb), Some(name)) => {
            Box::pin(started(&desk, domain, Mutation::Service(name, verb))).await
        }
        (ServiceOp::Status | ServiceOp::Log | ServiceOp::Act(_), None) => return Err(missing()),
    })
}

/// A service's state in the page's words.
fn said_state(desk: &Desk<'_>, service: &str, state: ServiceState) -> String {
    let mut args = FluentArgs::new();
    args.set("name", service.to_owned());
    let key = if state == ServiceState::Running {
        keys::WEB_SYSTEM_ENTWARE_SSH_RUNNING
    } else {
        keys::WEB_SYSTEM_ENTWARE_SSH_STOPPED
    };
    tr(desk.locale(), key, Some(&args))
}
