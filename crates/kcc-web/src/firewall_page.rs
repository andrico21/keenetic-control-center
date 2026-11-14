//! The firewall page of one router, built on the domain page kit.
//!
//! It shows the IPv4 access lists with their rules in the order the router checks them and
//! where each list applies (interface and direction); rules are added, moved up and down
//! (buttons, no dragging), disabled and enabled, described, scheduled and removed, and
//! lists are applied to interfaces and taken off them. IPv6 access lists appear only when
//! the router's command catalog has them; otherwise a note links the command explorer.
//! UPnP redirects are listed read only.
//!
//! Routes (route table: `Read` and the router scope; every change opens its operation
//! through the kit, which re-checks the operation's permissions and audits the change; a
//! change to the traffic of the interface that carries kcc's connection asks first and
//! runs inside the fail-safe timer):
//!
//! - `GET /ui/r/{router}/firewall`: the access lists; `GET|POST .../firewall/rule/new`.
//! - `POST .../firewall/rule/{move|state}?list=&index=&rule=&...`;
//!   `GET|POST .../firewall/rule/{description|schedule|remove}?list=&index=&rule=`.
//! - `GET /ui/r/{router}/firewall/interfaces`: the lists applied to interfaces;
//!   `GET|POST .../firewall/bind`, `GET|POST .../firewall/unbind?interface=&list=&direction=`.
//! - `GET /ui/r/{router}/firewall/upnp`: the UPnP redirects.

mod bind;
mod bind_form;
mod checks;
mod expect;
mod lines;
mod lists_region;
mod regions;
mod rule;
mod rule_actions;
mod rule_forms;
mod rule_props;
mod rules_table;
mod run;
mod snapshot;
mod views;
pub(crate) mod wiring;
