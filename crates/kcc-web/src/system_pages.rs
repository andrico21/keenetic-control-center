//! The router's system pages under `/ui/r/{router}/system/...`.
//!
//! Router users, services, components and firmware, storage, Entware, schedules, KeenDNS,
//! the log and diagnostics. The general page (`system_general`) is the page kit's reference page
//! and shares their tabs.
//!
//! Every page reads its domain through the router's catalog and shows only the controls
//! the role may use; every change re-checks the permissions of its operation, asks for the
//! confirmation its risk needs (management changes explain the fail-safe timer,
//! destructive ones need the router name typed) and runs through the change workflow.
//!
//! Routes (route table: `Read` and the router's scope):
//!
//! - `GET /ui/r/{router}/system/users` and `POST` (create), `GET .../users/new`,
//!   `GET|POST .../users/tags`, `GET|POST .../users/delete`: router accounts and their
//!   service tags (`ManageUsers`, management risk).
//! - `GET /ui/r/{router}/system/services`, `POST .../services/toggle?name=&on=`: services
//!   on and off; HTTP, SSH and Telnet carry management access and ask first.
//! - `GET /ui/r/{router}/system/components`, `POST .../components/check`,
//!   `POST .../components/queue?name=&action=install|remove`, `POST .../components/commit`:
//!   the firmware, the component queue and the commit job that restarts the router.
//! - `GET /ui/r/{router}/system/storage`, `POST .../storage/eject?media=`: media and USB
//!   devices; the eject is destructive. `POST .../storage/initialize?media=` prepares a
//!   medium for Entware (ext4, destructive). Ejecting or initializing the drive Entware
//!   runs from asks a second time and passes `entware_ok=yes` only after it.
//! - `GET /ui/r/{router}/system/entware`, `POST .../entware/chroot?on=`,
//!   `POST .../entware/timezone`, `POST .../entware/initrc` (destructive),
//!   `POST .../entware/dns-override?on=` (management), `POST .../entware/remove`
//!   (destructive), `POST .../entware/setup` (destructive, a job): Entware's status, its
//!   `opkg` settings, the removal and the guided setup.
//! - `GET /ui/r/{router}/system/schedules` and `POST` (create), `GET .../schedules/new`,
//!   `GET|POST .../schedules/action`: schedules and their timed actions (writes).
//! - `GET /ui/r/{router}/system/keendns`, `GET|POST .../keendns/book`,
//!   `POST .../keendns/drop`, `POST .../keendns/access?level=`, `GET|POST .../keendns/proxy`:
//!   the KeenDNS name, remote access and web proxy entries (the last two management).
//! - `GET /ui/r/{router}/system/logs[?q=]`, `GET .../logs/download`: the router log,
//!   filtered, followed live and downloadable (reads; downloads are audited).
//! - `GET /ui/r/{router}/system/diagnostics` and `POST`: ping, traceroute, ARP ping and
//!   iperf3, each started as a job (reads).
//! - Jobs: `GET /ui/sse/r/{router}/system/jobs/{job}` follows a job the pages started,
//!   `POST .../system/jobs/{job}/cancel` stops a diagnostic.
//! - Streams (merged outside the request timeout, capped per session): the job stream
//!   above and `GET /ui/sse/r/{router}/system/logs[?q=]`, the live log.

mod component_commit;
mod component_queue;
mod components;
mod diagnostic_form;
mod diagnostic_lines;
mod diagnostics;
mod entware;
mod entware_actions;
mod entware_change;
mod entware_labels;
mod entware_setup;
pub(crate) mod entware_ssh;
mod entware_ssh_confirm;
mod entware_ssh_desk;
mod entware_ssh_enrol;
mod entware_ssh_errors;
mod entware_ssh_ops;
mod entware_ssh_services;
mod entware_ssh_views;
pub(crate) mod job_feed;
mod jobs;
mod keendns;
mod keendns_access;
mod keendns_forms;
mod log_collector;
pub(crate) mod log_poller;
mod log_source;
mod logs;
mod schedule_actions;
mod schedule_forms;
mod schedules;
mod service_toggle;
mod services;
pub(crate) mod shared;
mod storage;
mod storage_actions;
mod storage_guard;
mod storage_tables;
mod tables;
pub(crate) mod tabs;
mod user_answers;
mod user_delete;
mod user_dialog;
mod user_forms;
mod users;

use axum::{
    Router,
    routing::{get, post},
};

use crate::WebState;

/// The page and action routes of the system pages.
pub(crate) fn routes() -> Router<WebState> {
    Router::new()
        .route(
            "/ui/r/{router}/system/users",
            get(users::page).post(user_forms::create),
        )
        .route(
            "/ui/r/{router}/system/users/new",
            get(user_dialog::new_dialog),
        )
        .route(
            "/ui/r/{router}/system/users/tags",
            get(user_dialog::tags_dialog).post(user_forms::set_tags),
        )
        .route(
            "/ui/r/{router}/system/users/delete",
            get(user_delete::delete_dialog).post(user_delete::delete),
        )
        .route("/ui/r/{router}/system/services", get(services::page))
        .route(
            "/ui/r/{router}/system/services/toggle",
            post(service_toggle::toggle),
        )
        .route("/ui/r/{router}/system/components", get(components::page))
        .route(
            "/ui/r/{router}/system/components/check",
            post(component_queue::check),
        )
        .route(
            "/ui/r/{router}/system/components/queue",
            post(component_queue::queue),
        )
        .route(
            "/ui/r/{router}/system/components/commit",
            post(component_commit::commit),
        )
        .route("/ui/r/{router}/system/storage", get(storage::page))
        .route(
            "/ui/r/{router}/system/storage/eject",
            post(storage_actions::eject),
        )
        .route(
            "/ui/r/{router}/system/schedules",
            get(schedules::page).post(schedule_forms::create),
        )
        .route(
            "/ui/r/{router}/system/schedules/new",
            get(schedule_forms::new_dialog),
        )
        .route(
            "/ui/r/{router}/system/schedules/action",
            get(schedule_actions::action_form).post(schedule_actions::add_action),
        )
        .route("/ui/r/{router}/system/keendns", get(keendns::page))
        .route(
            "/ui/r/{router}/system/keendns/book",
            get(keendns_forms::book_dialog).post(keendns_forms::book),
        )
        .route(
            "/ui/r/{router}/system/keendns/drop",
            post(keendns_forms::drop_name),
        )
        .route(
            "/ui/r/{router}/system/keendns/access",
            post(keendns_access::access),
        )
        .route(
            "/ui/r/{router}/system/keendns/proxy",
            get(keendns_access::proxy_dialog).post(keendns_access::proxy),
        )
        .route("/ui/r/{router}/system/logs", get(logs::page))
        .route("/ui/r/{router}/system/logs/download", get(logs::download))
        .route(
            "/ui/r/{router}/system/diagnostics",
            get(diagnostics::page).post(diagnostics::start),
        )
        .route(
            "/ui/r/{router}/system/jobs/{job}/cancel",
            post(jobs::cancel),
        )
        .merge(entware_routes())
}

/// The routes of the Entware page and of the storage page's Prepare for Entware.
fn entware_routes() -> Router<WebState> {
    Router::new()
        .route(
            "/ui/r/{router}/system/storage/initialize",
            post(storage_actions::initialize),
        )
        .route("/ui/r/{router}/system/entware", get(entware::page))
        .route(
            "/ui/r/{router}/system/entware/chroot",
            post(entware_actions::chroot),
        )
        .route(
            "/ui/r/{router}/system/entware/timezone",
            post(entware_actions::timezone),
        )
        .route(
            "/ui/r/{router}/system/entware/initrc",
            post(entware_actions::initrc),
        )
        .route(
            "/ui/r/{router}/system/entware/dns-override",
            post(entware_actions::dns_override),
        )
        .route(
            "/ui/r/{router}/system/entware/remove",
            post(entware_actions::remove),
        )
        .route(
            "/ui/r/{router}/system/entware/setup",
            post(entware_setup::setup),
        )
        .merge(entware_ssh::routes())
}

/// The event-stream routes of the system pages, merged outside the request timeout.
pub(crate) fn streams() -> Router<WebState> {
    Router::new()
        .route("/ui/sse/r/{router}/system/jobs/{job}", get(jobs::stream))
        .route("/ui/sse/r/{router}/system/logs", get(logs::stream))
}
