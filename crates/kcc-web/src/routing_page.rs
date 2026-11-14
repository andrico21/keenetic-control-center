//! The routing pages of one router, built on the domain page kit.
//!
//! Static routes (IPv4 and IPv6) are added and removed through the routing domain's
//! route-wipe guard; the routing table is read only; connection policies list their
//! interfaces in order and multipath. The port forwarding and firewall pages share the
//! family's tabs and the page [`frame`] (`DESIGN.md`, "Domain page kit").
//!
//! Routes (route table: `Read` and the router scope; every change opens its operation
//! through the kit, which re-checks the operation's permissions and audits the change):
//!
//! - `GET /ui/r/{router}/routing[/ipv6]`: the static routes;
//!   `GET|POST .../routing/route/new?family=`: Add route;
//!   `GET|POST .../routing/route/remove?family=&destination=&...`: Remove route, guarded.
//! - `GET /ui/r/{router}/routing/table[/ipv6]`: the routing table.
//! - `GET /ui/r/{router}/routing/policies`: connection policies;
//!   `GET|POST .../routing/policy/{new|description|permit}`, `POST
//!   .../routing/policy/{multipath|unpermit}`, `GET|POST .../routing/policy/delete`.

pub(crate) mod frame;
mod guard;
mod policy_actions;
mod policy_change;
mod policy_dialogs;
mod policy_forms;
mod policy_rows;
mod policy_view;
pub(crate) mod reply;
mod route_add;
mod route_form;
mod route_remove;
pub(crate) mod route_rows;
mod route_views;
mod table_rows;
mod tables;
pub(crate) mod wiring;
