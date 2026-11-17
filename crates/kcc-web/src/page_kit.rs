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
//! - [`confirm`]: which changes ask first and in which words, and the one confirmation
//!   dialog; management changes explain the fail-safe timer, destructive ones need the
//!   router name typed. A request's stakes are the one decision the gate and the dialog
//!   follow, so a destructive management change asks for the name in the timer's words.
//!   The typed-name delete of objects that are not routers uses the same dialog.
//! - [`family`]: the page family, whose words the confirmations and the outcomes use.
//! - [`outcome`] and [`failure`]: a success toast and the unsaved badge, or a localized
//!   error with the router's own message in a collapsible "router said" block.
//! - [`change`]: the change workflow run (backup, conflict check, read-back, audit), with
//!   the fail-safe timer around management changes.
//! - [`form`]: the dialog forms, from a one-field edit to a whole configuration.
//! - [`audit`]: one record per action with field names, never values.
//! - [`facts`]: the router's catalog, cached, so validation never contacts the router.
//! - [`respond`]: the htmx answers: redirects, retargets, the shared dialog and the answer
//!   to a change (its outcome, what the page adds, the region read back).
//! - [`request`]: what a page reads from a request: its parameters (the last value of a
//!   name counts), the page the browser shows, and the addresses of its actions.
//! - [`secret`]: write-only secret fields, and secret members masked in raw answers.
//! - [`values`]: typed values several page families read from their forms, such as a
//!   port or a netmask.

pub(crate) mod action;
pub(crate) mod audit;
pub(crate) mod change;
pub(crate) mod confirm;
pub(crate) mod context;
pub(crate) mod facts;
pub(crate) mod failure;
pub(crate) mod family;
pub(crate) mod form;
pub(crate) mod gate;
pub(crate) mod outcome;
pub(crate) mod request;
pub(crate) mod respond;
pub(crate) mod secret;
pub(crate) mod submit;
pub(crate) mod values;
