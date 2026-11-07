//! `kcc_<area>_write`: typed writes through the curated domain planners and `ChangeSet`.

mod clients;
mod common;
pub(crate) mod dispatch;
mod dns;
mod filtering;
mod housekeeping;
mod interfaces;
mod jobs;
mod routing;
mod services;
mod system;
mod vpn;
mod vpn_servers;
mod wifi;
