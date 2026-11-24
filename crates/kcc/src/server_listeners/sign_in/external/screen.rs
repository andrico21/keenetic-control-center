//! The build-time SSRF screen of the JWKS host.
//!
//! A host that resolves to an address the kit blocks refuses the build with the address
//! class, unless kcc.toml's allowlist admits it; a cloud metadata address is refused
//! whatever the allowlist says.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::net::ToSocketAddrs as _;

use kcc_app::settings::mcp_schema::OidcConfig;
use url::Url;

use super::ProviderRefusal;

/// Refuses a JWKS URL whose host resolves to an address the kit blocks and kcc.toml's
/// allowlist does not admit.
///
/// A host that does not resolve now passes: the kit resolves and screens it again on every
/// fetch.
///
/// # Errors
///
/// [`ProviderRefusal::PrivateAddress`] or [`ProviderRefusal::Metadata`].
pub(super) fn screen(jwks: &Url, allowlist: &OidcConfig) -> Result<(), ProviderRefusal> {
    let port = jwks.port_or_known_default().unwrap_or(443);
    screened(jwks.host_str().unwrap_or_default(), allowlist, |host| {
        (host, port)
            .to_socket_addrs()
            .ok()
            .map(|found| found.map(|address| address.ip()).collect())
    })
}

/// [`screen`] for `host`, whose addresses `resolve` finds (`None`: it does not resolve).
///
/// # Errors
///
/// As [`screen`].
fn screened(
    host: &str,
    allowlist: &OidcConfig,
    resolve: impl FnOnce(&str) -> Option<Vec<IpAddr>>,
) -> Result<(), ProviderRefusal> {
    let name = host.trim_end_matches('.').to_ascii_lowercase();
    let admitted_host = allowlist.ssrf_allow_hosts.iter().any(|allowed| {
        allowed
            .trim()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(&name)
    });
    let refused = |reason| ProviderRefusal::PrivateAddress {
        host: host.to_owned(),
        reason,
    };
    if [".localhost", ".local", ".internal"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
        && !admitted_host
    {
        return Err(refused("internal_hostname"));
    }
    let Some(addresses) = resolve(host) else {
        tracing::warn!(
            host,
            "the identity provider's JWKS host does not resolve now"
        );
        return Ok(());
    };
    for ip in addresses {
        let Some(reason) = blocked(ip) else { continue };
        if reason == METADATA {
            return Err(ProviderRefusal::Metadata {
                host: host.to_owned(),
            });
        }
        let admitted = admitted_host
            || allowlist
                .ssrf_allow_cidrs
                .iter()
                .any(|cidr| cidr.contains(&ip));
        if !admitted {
            return Err(refused(reason));
        }
    }
    Ok(())
}

/// The class of a cloud metadata address, which no allowlist admits.
const METADATA: &str = "cloud_metadata";

/// The class of an address the kit's SSRF screen blocks; `None` for a public one. A subset
/// of the kit's rules: what this misses, the kit refuses at fetch time.
fn blocked(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| blocked_v6(v6), blocked_v4),
    }
}

/// [`blocked`] for IPv4.
fn blocked_v4(v4: Ipv4Addr) -> Option<&'static str> {
    let [first, second, third, _fourth] = v4.octets();
    if v4 == Ipv4Addr::new(169, 254, 169, 254) || v4 == Ipv4Addr::new(100, 100, 100, 200) {
        Some(METADATA)
    } else if first == 0 {
        Some("this_network")
    } else if v4.is_loopback() {
        Some("loopback")
    } else if v4.is_broadcast() {
        Some("broadcast")
    } else if v4.is_private() {
        Some("private_rfc1918")
    } else if v4.is_link_local() {
        Some("link_local")
    } else if v4.is_multicast() {
        Some("multicast")
    } else if first == 100 && (second & 0b1100_0000) == 0b0100_0000 {
        Some("cgnat")
    } else if matches!(
        (first, second, third),
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
    ) {
        Some("documentation")
    } else if first == 198 && matches!(second, 18 | 19) {
        Some("benchmarking")
    } else if first >= 240 {
        Some("reserved")
    } else {
        None
    }
}

/// [`blocked`] for IPv6 that is not IPv4-mapped.
fn blocked_v6(v6: Ipv6Addr) -> Option<&'static str> {
    let segments = v6.segments();
    let [head, next, ..] = segments;
    if v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
        || v6 == Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254)
    {
        Some(METADATA)
    } else if v6.is_loopback() {
        Some("loopback")
    } else if v6.is_unspecified() {
        Some("unspecified")
    } else if v6.is_multicast() {
        Some("multicast")
    } else if (head & 0xffc0) == 0xfe80 {
        Some("link_local")
    } else if (head & 0xffc0) == 0xfec0 {
        Some("site_local")
    } else if (head & 0xfe00) == 0xfc00 {
        Some("unique_local")
    } else if head == 0x2001 && next == 0x0db8 {
        Some("documentation")
    } else {
        None
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    clippy::missing_panics_doc,
    reason = "test assertions deliberately panic"
)]
mod tests {
    use core::{error::Error, net::IpAddr};

    use kcc_app::settings::{Config, mcp_schema::OidcConfig};

    use super::{ProviderRefusal, screened};

    type TestResult = Result<(), Box<dyn Error>>;

    /// The `[mcp.auth.oidc]` table of kcc.toml with `allowlist`.
    fn allowing(allowlist: &str) -> Result<OidcConfig, Box<dyn Error>> {
        Ok(
            Config::from_toml_str(&format!("[mcp.auth.oidc]\n{allowlist}"))?
                .mcp
                .auth
                .oidc,
        )
    }

    /// The refusal of `host` resolving to `address` under `allowlist`, as text.
    fn outcome(host: &str, address: &str, allowlist: &str) -> Result<String, Box<dyn Error>> {
        let ip: IpAddr = address.parse()?;
        Ok(
            match screened(host, &allowing(allowlist)?, |_host| Some(vec![ip])) {
                Ok(()) => "ok".to_owned(),
                Err(ProviderRefusal::PrivateAddress { host: _, reason }) => reason.to_owned(),
                Err(ProviderRefusal::Metadata { host: _ }) => "metadata".to_owned(),
                Err(other) => format!("{other:?}"),
            },
        )
    }

    /// Regression (todo 33): every private address class is refused with its reason.
    ///
    /// IPv4 and IPv6 loopback, RFC 1918, link-local, unique local, an IPv4-mapped private
    /// address; a public address passes.
    #[test]
    fn each_private_class_is_refused_with_its_reason() -> TestResult {
        let private_v4 = format!("{}.1.2.3", 10_u8);
        let mapped = format!("::ffff:{private_v4}");
        let rows = [
            ("::1", "loopback"),
            (private_v4.as_str(), "private_rfc1918"),
            ("169.254.10.1", "link_local"),
            ("fd12:3456::1", "unique_local"),
            ("fe80::1", "link_local"),
            (mapped.as_str(), "private_rfc1918"),
            ("::ffff:127.0.0.1", "loopback"),
            ("93.184.215.14", "ok"),
            ("2a00:1450::1", "ok"),
        ];
        for (address, expected) in rows {
            assert_eq!(outcome("idp.example", address, "")?, expected, "{address}");
        }
        Ok(())
    }

    /// Regression (todo 33): the allowlist never admits a cloud metadata address.
    ///
    /// It admits the private range around it (IPv4 and IPv6) and the host by name.
    #[test]
    fn the_metadata_address_stays_refused_under_an_allowlist() -> TestResult {
        let link_local = "ssrf_allow_cidrs = [\"169.254.0.0/16\", \"fd00::/8\"]";
        assert_eq!(outcome("idp.example", "169.254.10.1", link_local)?, "ok");
        assert_eq!(outcome("idp.example", "fd00:1::1", link_local)?, "ok");
        assert_eq!(
            outcome("idp.example", "169.254.169.254", link_local)?,
            "metadata"
        );
        assert_eq!(
            outcome("idp.example", "fd00:ec2::254", link_local)?,
            "metadata"
        );
        let by_name = "ssrf_allow_hosts = [\"idp.example\"]";
        assert_eq!(
            outcome("idp.example", "169.254.169.254", by_name)?,
            "metadata"
        );
        Ok(())
    }

    /// Regression (todo 33): an internal host name is refused unless kcc.toml names it.
    ///
    /// `.local`, `.internal` and `.localhost` are refused before the host is resolved.
    #[test]
    fn internal_host_names_are_refused_unless_named() -> TestResult {
        for host in ["idp.internal", "IdP.Local.", "auth.localhost"] {
            let refused = screened(host, &allowing("")?, |_host| None);
            assert!(
                matches!(
                    &refused,
                    Err(ProviderRefusal::PrivateAddress { host: named, reason: "internal_hostname" })
                        if named == host
                ),
                "{host}: {refused:?}"
            );
        }
        let named = allowing("ssrf_allow_hosts = [\"idp.internal\"]")?;
        screened("idp.internal", &named, |_host| None)?;
        screened("idp.example", &allowing("")?, |_host| None)?;
        Ok(())
    }
}
