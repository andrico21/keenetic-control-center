//! Non-secret WireGuard import fields and address parsing.

use core::net::Ipv4Addr;

use kcc_catalog::ValidationIssue;

use super::{VpnClientChange, WireGuardConfig, change};
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// Appends every documented non-secret peer field to the aggregate plan.
///
/// # Errors
///
/// Returns an error when the change workflow fails: dispatch, read-back or audit
/// ([`DomainError::Workflow`]), or when a reply or a plan does not have the expected shape
/// ([`DomainError::InvalidResponse`]).
pub(super) fn append(
    router: &RouterCtx,
    name: &str,
    config: &WireGuardConfig,
    operation: &mut ChangeOp,
) -> Result<()> {
    let mut changes = Vec::new();
    if let Some(port) = config.interface.listen_port {
        changes.push(VpnClientChange::WireGuardListenPort {
            name: name.to_owned(),
            port,
        });
    }
    for peer in &config.peers {
        changes.push(VpnClientChange::WireGuardPeer {
            name: name.to_owned(),
            public_key: peer.public_key.clone(),
        });
        if let Some(endpoint) = &peer.endpoint {
            let (address, port) = endpoint
                .rsplit_once(':')
                .ok_or(DomainError::InvalidResponse)?;
            changes.push(VpnClientChange::WireGuardEndpoint {
                name: name.to_owned(),
                public_key: peer.public_key.clone(),
                address: address.trim_matches(['[', ']']).to_owned(),
                port: port
                    .parse()
                    .map_err(|_error| DomainError::InvalidResponse)?,
            });
        }
        for prefix in &peer.allowed_ips {
            let (address, mask) = parse_prefix(prefix)?;
            changes.push(VpnClientChange::WireGuardAllowedIp {
                name: name.to_owned(),
                public_key: peer.public_key.clone(),
                address,
                mask,
            });
        }
        if let Some(seconds) = peer.persistent_keepalive {
            changes.push(VpnClientChange::WireGuardKeepalive {
                name: name.to_owned(),
                public_key: peer.public_key.clone(),
                seconds,
            });
        }
    }
    for field in changes {
        change::append(router, operation, &field)?;
    }
    Ok(())
}

/// Converts an imported IPv4 prefix to the catalog address/mask pair; any other address
/// (an IPv6 range) is refused as an invalid `address`.
///
/// # Errors
///
/// Returns an error when the catalog refuses a planned request
/// ([`DomainError::Validation`]), or when a reply or a plan does not have the expected
/// shape ([`DomainError::InvalidResponse`]).
fn parse_prefix(prefix: &str) -> Result<(String, String)> {
    let (address, prefix_length) = prefix.split_once('/').ok_or(DomainError::InvalidResponse)?;
    let bits = prefix_length
        .parse::<u32>()
        .map_err(|_error| DomainError::InvalidResponse)?;
    if address.parse::<Ipv4Addr>().is_err() {
        return Err(DomainError::Validation {
            issues: vec![ValidationIssue::InvalidValue {
                field: "address".to_owned(),
            }],
        });
    }
    if bits > 32 {
        return Err(DomainError::InvalidResponse);
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX
            .checked_shl(32_u32.saturating_sub(bits))
            .ok_or(DomainError::InvalidResponse)?
    };
    Ok((address.to_owned(), Ipv4Addr::from(mask).to_string()))
}
