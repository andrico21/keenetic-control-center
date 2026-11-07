//! Protected IPv6 route removal and wipe recovery.

use kcc_app::workflow::{ChangeSet, CliChangeResult};

use super::{plan_add_ipv6, plan_remove_ipv6, reports_cleared, request};
use crate::{
    DomainError, Result, RouterCtx,
    routing::{
        model::{Ipv6Route, RouteTableEntry},
        read,
    },
};

/// Removes one IPv6 route through the guarded workflow.
pub(super) async fn remove(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    route: &Ipv6Route,
) -> Result<CliChangeResult> {
    let before_table = read::ipv6_table(router).await?;
    let before = before_table.len();
    let removal = plan_remove_ipv6(router, route)?;
    let result = changes.apply_cli(request(&removal)?).await?;
    if reports_cleared(&result.responses) {
        for saved in before_table.iter().filter_map(configured_ipv6_route) {
            let restore = plan_add_ipv6(router, &saved?)?;
            drop(changes.apply_cli(request(&restore)?).await?);
        }
        return Err(DomainError::SafetyAbort);
    }
    let after = read::ipv6_table(router).await?.len();
    if before.checked_sub(after) != Some(1) {
        return Err(DomainError::RouteCountMismatch);
    }
    Ok(result)
}

/// Reconstructs one configured static IPv6 route from its command tail.
fn configured_ipv6_route(entry: &RouteTableEntry) -> Option<Result<Ipv6Route>> {
    if entry.is_static != Some(true) {
        return None;
    }
    Some(match entry.command.as_slice() {
        [prefix, gateway] => Ok(Ipv6Route::via_gateway(prefix, gateway)),
        [prefix, gateway, interface] => {
            Ok(Ipv6Route::via_gateway(prefix, gateway).on_interface(interface))
        }
        _ => Err(DomainError::InvalidResponse),
    })
}
