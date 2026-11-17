//! Static routes read from the running configuration and their wipe recovery.

use core::{
    net::{Ipv4Addr, Ipv6Addr},
    str::from_utf8,
};

use kcc_app::workflow::ChangeSet;
use kcc_rci::ConfigKind;
use secrecy::ExposeSecret as _;

use super::{plan_add_ipv4, plan_add_ipv6, request};
use crate::{
    ChangeOp, DomainError, Result, RouterCtx,
    routing::model::{Ipv4Route, Ipv6Route},
};

/// Words of an `ip route` or `ipv6 route` the typed route model cannot carry.
const UNSUPPORTED: [&str; 2] = ["auto", "reject"];

/// One saved static route, or the reason it cannot be restored.
pub(super) type Saved<T> = Result<T>;

/// Reads every configured IPv4 static route from the running configuration.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub(super) async fn saved_ipv4(router: &RouterCtx) -> Result<Vec<Saved<Ipv4Route>>> {
    let text = running_config(router).await?;
    Ok(route_words(&text, "ip")
        .into_iter()
        .map(|words| ipv4_route(&words))
        .collect())
}

/// Reads every configured IPv6 static route from the running configuration.
// cancel-safe: a single read request; cancellation changes nothing on the router.
pub(super) async fn saved_ipv6(router: &RouterCtx) -> Result<Vec<Saved<Ipv6Route>>> {
    let text = running_config(router).await?;
    Ok(route_words(&text, "ipv6")
        .into_iter()
        .map(|words| ipv6_route(&words))
        .collect())
}

/// Re-adds every saved IPv4 route, then returns the first failure, or the safety abort.
// NOT cancel-safe: cancelled mid-restore, the routes not yet re-added stay removed.
pub(super) async fn restore_ipv4(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    saved: Vec<Saved<Ipv4Route>>,
) -> DomainError {
    restore_all(changes, saved, |route| plan_add_ipv4(router, route)).await
}

/// Re-adds every saved IPv6 route, then returns the first failure, or the safety abort.
// NOT cancel-safe: cancelled mid-restore, the routes not yet re-added stay removed.
pub(super) async fn restore_ipv6(
    changes: &mut ChangeSet,
    router: &RouterCtx,
    saved: Vec<Saved<Ipv6Route>>,
) -> DomainError {
    restore_all(changes, saved, |route| plan_add_ipv6(router, route)).await
}

/// Restores every entry, never stopping at a failure, and reports the first one.
// NOT cancel-safe: cancelled mid-restore, the routes not yet re-added stay removed.
async fn restore_all<T>(
    changes: &mut ChangeSet,
    saved: Vec<Saved<T>>,
    plan: impl Fn(&T) -> Result<ChangeOp>,
) -> DomainError {
    let mut first_error = None;
    for entry in saved {
        let outcome = match entry.and_then(|route| request(&plan(&route)?)) {
            Ok(restore) => changes
                .apply_cli(restore)
                .await
                .map(drop)
                .map_err(DomainError::from),
            Err(error) => Err(error),
        };
        if let Err(error) = outcome {
            first_error = first_error.or(Some(error));
        }
    }
    first_error.unwrap_or(DomainError::SafetyAbort)
}

/// Downloads the running configuration text.
// cancel-safe: a single read request; cancellation changes nothing on the router.
async fn running_config(router: &RouterCtx) -> Result<String> {
    let bytes = router.client.download_config(ConfigKind::Running).await?;
    from_utf8(bytes.expose_secret())
        .map(str::to_owned)
        .map_err(|_error| DomainError::InvalidResponse)
}

/// Words after `<family> route` of every top-level route line.
fn route_words<'text>(text: &'text str, family: &str) -> Vec<Vec<&'text str>> {
    text.lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            (line.starts_with(family)
                && words.next() == Some(family)
                && words.next() == Some("route"))
            .then(|| words.collect())
        })
        .collect()
}

/// Rebuilds an IPv4 route from the words after `ip route`.
fn ipv4_route(words: &[&str]) -> Result<Ipv4Route> {
    let (destination, mask, tail) = match words {
        ["default", tail @ ..] => ("default", None, tail),
        [network, mask, tail @ ..] if is_netmask(mask) => (*network, Some(*mask), tail),
        [host, tail @ ..] => (*host, None, tail),
        [] => return Err(DomainError::InvalidResponse),
    };
    let mut route = Ipv4Route {
        destination: destination.to_owned(),
        mask: mask.map(ToOwned::to_owned),
        gateway: None,
        interface: None,
        metric: None,
    };
    for word in tail {
        if UNSUPPORTED.contains(word) || route.metric.is_some() {
            return Err(DomainError::InvalidResponse);
        }
        if word.parse::<Ipv4Addr>().is_ok() && route.gateway.is_none() && route.interface.is_none()
        {
            route.gateway = Some((*word).to_owned());
        } else if let Ok(metric) = word.parse::<u32>() {
            route.metric = Some(metric);
        } else if route.interface.is_none() {
            route.interface = Some((*word).to_owned());
        } else {
            return Err(DomainError::InvalidResponse);
        }
    }
    if route.gateway.is_none() && route.interface.is_none() {
        return Err(DomainError::InvalidResponse);
    }
    Ok(route)
}

/// Rebuilds an IPv6 route from the words after `ipv6 route`.
fn ipv6_route(words: &[&str]) -> Result<Ipv6Route> {
    let [prefix, tail @ ..] = words else {
        return Err(DomainError::InvalidResponse);
    };
    let mut route = Ipv6Route {
        prefix: (*prefix).to_owned(),
        gateway: None,
        interface: None,
    };
    for word in tail {
        if word.parse::<Ipv6Addr>().is_ok() && route.gateway.is_none() {
            route.gateway = Some((*word).to_owned());
        } else if route.interface.is_none()
            && route.gateway.is_none()
            && !UNSUPPORTED.contains(word)
            && !word.contains([':', '%'])
        {
            route.interface = Some((*word).to_owned());
        } else {
            return Err(DomainError::InvalidResponse);
        }
    }
    if route.gateway.is_none() && route.interface.is_none() {
        return Err(DomainError::InvalidResponse);
    }
    Ok(route)
}

/// Whether the word is a contiguous IPv4 netmask.
fn is_netmask(word: &str) -> bool {
    word.parse::<Ipv4Addr>().is_ok_and(|mask| {
        let bits = u32::from(mask);
        bits.leading_ones().saturating_add(bits.trailing_zeros()) == 32
    })
}
