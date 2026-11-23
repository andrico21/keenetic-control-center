//! The `entware-ssh` toolset over a real session against the fake router and the fake
//! Entware SSH server: the registry, visibility and the live gates, the safety gates of
//! every operation, the boundary checks, and the parsed, cleaned and paged results.
extern crate alloc;

#[path = "entware_ssh_tools/bounds.rs"]
mod bounds;
#[path = "entware_ssh_tools/cancel.rs"]
mod cancel;
#[path = "entware_ssh_tools/gating.rs"]
mod gating;
#[path = "entware_ssh_tools/paging.rs"]
mod paging;
#[path = "entware_ssh_tools/registry.rs"]
mod registry;
#[path = "entware_ssh_tools/results.rs"]
mod results;
#[path = "entware_ssh_tools/rig.rs"]
mod rig;
#[path = "entware_ssh_tools/support.rs"]
mod support;
#[path = "entware_ssh_tools/visibility.rs"]
mod visibility;
