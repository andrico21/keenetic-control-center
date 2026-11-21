//! SSH address admission tests.

use core::{
    error::Error,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use super::{AllowedNetwork, OutboundPolicy};
use crate::{RciError, RouterUrl};

type TestResult = Result<(), Box<dyn Error>>;

/// The SSH port every test asks for; the router URL's HTTP port must not leak through.
const SSH_PORT: u16 = 222;

/// A globally routable address, the kind a DNS suffix may admit for RCI.
const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

/// An RFC 5737 address inside the test network.
const LAN: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

/// A policy admitting `192.0.2.0/24`.
fn lan_policy() -> Result<OutboundPolicy, RciError> {
    let network = AllowedNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)?;
    Ok(OutboundPolicy::default().with_allowed_networks(vec![network]))
}

/// Socket addresses on the HTTP port, as the resolver returns them.
fn resolved(addresses: &[IpAddr]) -> Vec<SocketAddr> {
    addresses
        .iter()
        .map(|address| SocketAddr::new(*address, 80))
        .collect()
}

/// Todo 6: an address inside `allowed_networks` is admitted, moved to the SSH port.
// cancel-safe: only reads the policy; a literal URL resolves without DNS.
#[tokio::test]
async fn address_in_allowed_network_is_admitted_on_the_ssh_port() -> TestResult {
    let router = "http://192.0.2.10:8080".parse::<RouterUrl>()?;
    let admitted = lan_policy()?.admit_ssh(&router, SSH_PORT).await?;
    assert_eq!(admitted, [SocketAddr::new(LAN, SSH_PORT)]);
    Ok(())
}

/// Todo 6: a public address admitted for RCI only through `allowed_suffixes` is refused
/// for SSH, and a mixed answer keeps only the address inside `allowed_networks`.
#[test]
fn suffix_only_public_address_is_refused() -> TestResult {
    let suffix_only = OutboundPolicy::default().with_allowed_suffixes(vec!["example.net".into()]);
    assert!(
        suffix_only.allows("router.example.net", PUBLIC),
        "precondition: RCI admits the public address through the suffix"
    );
    assert!(matches!(
        suffix_only.ssh_addresses("router.example.net", &resolved(&[PUBLIC]), SSH_PORT),
        Err(RciError::Policy)
    ));
    let mixed = lan_policy()?.with_allowed_suffixes(vec!["example.net".into()]);
    assert_eq!(
        mixed.ssh_addresses("router.example.net", &resolved(&[PUBLIC, LAN]), SSH_PORT)?,
        [SocketAddr::new(LAN, SSH_PORT)]
    );
    Ok(())
}

/// Todo 6: loopback is refused unless the policy admits loopback.
// cancel-safe: only reads the policy; literal URLs resolve without DNS.
#[tokio::test]
async fn loopback_is_refused_unless_admitted() -> TestResult {
    for url in ["http://127.0.0.1", "http://[::1]"] {
        let router = url.parse::<RouterUrl>()?;
        assert!(
            matches!(
                lan_policy()?.admit_ssh(&router, SSH_PORT).await,
                Err(RciError::Policy)
            ),
            "{url} refused by default"
        );
        let admitted = lan_policy()?
            .with_loopback(true)
            .admit_ssh(&router, SSH_PORT)
            .await?;
        assert_eq!(admitted.len(), 1, "{url} admitted with loopback");
        assert!(
            admitted
                .iter()
                .all(|address| address.ip().is_loopback() && address.port() == SSH_PORT)
        );
    }
    Ok(())
}

/// Todo 6: metadata addresses are refused even when a configured network and loopback
/// would otherwise cover them.
// cancel-safe: only reads the policy; literal URLs resolve without DNS.
#[tokio::test]
async fn metadata_addresses_are_always_refused() -> TestResult {
    let wide = OutboundPolicy::default()
        .with_allowed_networks(vec![
            AllowedNetwork::new(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16)?,
            AllowedNetwork::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10)?,
            AllowedNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)?,
        ])
        .with_loopback(true);
    for url in ["http://169.254.169.254", "http://100.100.100.200"] {
        let router = url.parse::<RouterUrl>()?;
        assert!(
            matches!(
                wide.admit_ssh(&router, SSH_PORT).await,
                Err(RciError::Policy)
            ),
            "{url} refused"
        );
    }
    let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    assert_eq!(
        wide.ssh_addresses("router.example.net", &resolved(&[metadata, LAN]), SSH_PORT)?,
        [SocketAddr::new(LAN, SSH_PORT)]
    );
    Ok(())
}
