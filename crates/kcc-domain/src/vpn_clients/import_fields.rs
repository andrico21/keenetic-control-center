//! Non-secret WireGuard import fields and address parsing.

use core::net::Ipv4Addr;

use super::{VpnClientChange, WireGuardConfig, change};
use crate::{ChangeOp, DomainError, Result, RouterCtx};

/// Appends every documented non-secret peer field to the aggregate plan.
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

/// Converts an imported prefix to the catalog address/mask pair.
fn parse_prefix(prefix: &str) -> Result<(String, String)> {
    let (address, prefix_length) = prefix.split_once('/').ok_or(DomainError::InvalidResponse)?;
    let bits = prefix_length
        .parse::<u32>()
        .map_err(|_error| DomainError::InvalidResponse)?;
    if address.contains(':') {
        return Ok((address.to_owned(), bits.to_string()));
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
