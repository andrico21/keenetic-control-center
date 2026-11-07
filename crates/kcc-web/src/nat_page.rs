//! The port forwarding page of one router, built on the domain page kit.
//!
//! It lists the forwarding rules (protocol, incoming interface, external ports, the device
//! forwarded to and the port there), the interfaces with address translation, and the
//! router's active connections one page of at most 200 at a time. Rules and translated
//! interfaces are added and removed through the NAT domain, which reads each change back.
//!
//! Routes (route table: `Read` and the router scope; every change opens its operation
//! through the kit, which re-checks the operation's permissions and audits the change):
//!
//! - `GET /ui/r/{router}/nat`: the rules; `GET|POST .../nat/forward/new`: Forward a port;
//!   `GET|POST .../nat/forward/remove?interface=&target=&...`: Remove.
//! - `GET /ui/r/{router}/nat/interfaces`: the translated interfaces;
//!   `GET|POST .../nat/interface/new`, `GET|POST .../nat/interface/remove?name=`.
//! - `GET /ui/r/{router}/nat/sessions?page=&q=&sort=&dir=`: the active connections.

mod actions;
mod forward_forms;
mod forwards;
mod interfaces;
mod session_rows;
mod sessions;
mod views;
pub(crate) mod wiring;
