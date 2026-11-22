//! Real Entware planner inputs for the registry guard.

use kcc_domain::{
    RouterCtx, entware,
    entware::{
        models::{Installer, TimezoneSetting},
        setup,
    },
};

use crate::{
    support::{TestResult, administrator},
    tests::checked,
};

/// Dispatches each Entware registry entry to its planner and conversion function.
pub(super) fn check(router: &RouterCtx, op: &str) -> TestResult {
    let role = administrator();
    let plan = match op {
        "setup" => {
            return checked(setup::install_request(
                router,
                "fixture-media:/",
                Installer::Aarch64,
            )?);
        }
        "remove" => entware::plan_remove(router, "router", &role, true)?,
        "chroot" => entware::plan_chroot(router, "router", &role, true)?,
        "timezone" => entware::plan_timezone(router, "router", &role, TimezoneSetting::Auto)?,
        "initrc" => {
            entware::plan_initrc(router, "router", &role, "/opt/etc/init.d/rc.unslung", true)?
        }
        "dns_override" => entware::plan_dns_override(router, "router", &role, true)?,
        _ => return Err("uncovered Entware operation".into()),
    };
    checked(entware::change_request(&plan.operation)?)
}
