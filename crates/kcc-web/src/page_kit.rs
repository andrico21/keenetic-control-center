//! The domain page kit: the machinery every router page shares, so a domain page is a
//! route, a view model, a form, a plan and one kit call.
//!
//! The contract every domain page follows (`DESIGN.md`, "Domain page kit"):
//!
//! - [`action`]: the kit call of a domain page: open an operation on the router of the
//!   route, confirm, run the change, render the outcome.
//! - [`context`]: the router named by the route is resolved and checked first (a malformed
//!   or invisible router is 404, a missing permission 403), and the page shell carries the
//!   fleet switcher with that router selected.
//! - [`gate`]: the permissions an operation needs; [`gate::Controls`] hides what the role
//!   may not do and every handler checks again before it acts.
//! - [`family`] and [`confirm`]: which changes ask first and in which words; management
//!   changes explain the fail-safe timer, destructive ones need the router name typed.
//!   [`stakes`] is the one decision both follow, so a destructive management change asks
//!   for the name in the timer's words. [`typed_name`] is the same for objects that are
//!   not routers.
//! - [`outcome`] and [`failure`]: a success toast and the unsaved badge, or a localized
//!   error with the router's own message in a collapsible "router said" block.
//! - [`change`]: the change workflow run (backup, conflict check, read-back, audit), with
//!   the fail-safe timer around management changes.
//! - [`dialog`]: the one-field edit dialog.
//! - [`audit`]: one record per action with field names, never values.
//! - [`facts`]: the router's catalog, cached, so validation never contacts the router.
//! - [`respond`]: the htmx answers: redirects, retargets, the shared dialog and the answer
//!   to a change (its outcome, what the page adds, the region read back).
//! - [`request`]: what a page reads from a request: its parameters (the last value of a
//!   name counts), the page the browser shows, and the addresses of its actions.
//! - [`secret`] and [`reveal`]: write-only secret fields, and the audited Reveal action
//!   that alone shows a stored secret.

pub(crate) mod action;
pub(crate) mod audit;
pub(crate) mod change;
pub(crate) mod confirm;
pub(crate) mod context;
pub(crate) mod dialog;
pub(crate) mod facts;
pub(crate) mod failure;
pub(crate) mod family;
pub(crate) mod gate;
pub(crate) mod outcome;
pub(crate) mod request;
pub(crate) mod respond;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the audited Reveal of the domain pages; its first page is the Wi-Fi PSK (todo 37)"
    )
)]
pub(crate) mod reveal;
pub(crate) mod secret;
pub(crate) mod stakes;
pub(crate) mod submit;
pub(crate) mod typed_name;
