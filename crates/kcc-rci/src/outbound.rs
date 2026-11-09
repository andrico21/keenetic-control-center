//! Router outbound policy, DNS pinning, and TLS verification modes.

use alloc::sync::Arc;
use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use std::net::ToSocketAddrs as _;

use reqwest::{Client, redirect::Policy};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, ring, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use tokio::task::spawn_blocking;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::{RciError, RouterUrl, session::HttpTimeouts};

/// Cloud metadata addresses that are refused regardless of configured networks.
const METADATA_ADDRESSES: [IpAddr; 3] = [
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
    IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
];

/// TLS verification policy for a router connection.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TlsMode {
    /// Validate the certificate chain and hostname with the normal web PKI roots.
    Verify,
    /// Require the SHA-256 digest of the leaf certificate's `SubjectPublicKeyInfo`.
    PinSha256([u8; 32]),
}

/// One CIDR network admitted by [`OutboundPolicy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AllowedNetwork {
    /// Canonical network address.
    address: IpAddr,
    /// CIDR prefix length.
    prefix_len: u8,
}

impl AllowedNetwork {
    /// Creates a canonical CIDR network.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Validation`] for an invalid prefix or host-bit address.
    #[inline]
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, RciError> {
        let bits = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > bits || network_address(address, prefix_len) != address {
            return Err(RciError::Validation);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    /// Whether `address` belongs to this network.
    #[inline]
    #[must_use]
    pub fn contains(self, address: IpAddr) -> bool {
        network_address(address, self.prefix_len) == self.address
    }
}

/// Operator-configured router target allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[expect(
    clippy::module_name_repetitions,
    reason = "the protocol API is explicitly named OutboundPolicy"
)]
pub struct OutboundPolicy {
    /// Networks admitted for ordinary router names and literals.
    allowed_networks: Vec<AllowedNetwork>,
    /// Hostname suffixes whose resolved public addresses are admitted.
    allowed_suffixes: Vec<String>,
    /// Whether loopback networks are admitted.
    allow_loopback: bool,
}

impl Default for OutboundPolicy {
    #[inline]
    fn default() -> Self {
        Self {
            allowed_networks: vec![
                network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
                network(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12),
                network(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16),
                network(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10),
                network(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0)), 8),
            ],
            allowed_suffixes: [
                ".keenetic.pro",
                ".keenetic.link",
                ".keenetic.name",
                ".keenetic.io",
                ".keenetic.net",
                // UNVERIFIED: published Netcraze cloud suffixes need live confirmation.
                ".netcraze.pro",
                ".netcraze.link",
                ".netcraze.io",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            allow_loopback: false,
        }
    }
}

impl OutboundPolicy {
    /// Validates and pins addresses supplied by a caller-controlled resolver.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Policy`] if the address set is empty or contains a forbidden target.
    #[doc(hidden)]
    #[inline]
    pub fn client_builder_for_resolved(
        &self,
        router: &RouterUrl,
        tls_mode: &TlsMode,
        timeouts: HttpTimeouts,
        resolved: &[SocketAddr],
    ) -> Result<reqwest::ClientBuilder, RciError> {
        let parsed = reqwest::Url::parse(router.as_str()).map_err(|_error| RciError::Policy)?;
        let host = parsed.host_str().ok_or(RciError::Policy)?;
        if resolved.is_empty()
            || resolved
                .iter()
                .any(|address| !self.allows(host, address.ip()))
        {
            return Err(RciError::Policy);
        }
        Self::pinned_builder(host, resolved, tls_mode, timeouts)
    }

    /// Replaces the admitted CIDR networks.
    #[inline]
    #[must_use]
    pub fn with_allowed_networks(mut self, networks: Vec<AllowedNetwork>) -> Self {
        self.allowed_networks = networks;
        self
    }

    /// Replaces the public-address hostname suffix allowlist.
    #[inline]
    #[must_use]
    pub fn with_allowed_suffixes(mut self, suffixes: Vec<String>) -> Self {
        self.allowed_suffixes = suffixes
            .into_iter()
            .filter_map(|suffix| {
                let normalized = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
                (!normalized.is_empty()).then_some(normalized)
            })
            .collect();
        self
    }

    /// Configures loopback admission.
    #[inline]
    #[must_use]
    pub const fn with_loopback(mut self, allow_loopback: bool) -> Self {
        self.allow_loopback = allow_loopback;
        self
    }

    /// Resolves, validates, and pins every address used for one router connection.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Policy`] when resolution fails, any address is forbidden, or TLS
    /// configuration cannot be built.
    // NOT cancel-safe: synchronous DNS may complete after the caller abandons construction, but
    // no request is sent and no externally visible state is changed.
    #[inline]
    pub async fn client_builder(
        &self,
        router: &RouterUrl,
        tls_mode: &TlsMode,
        timeouts: HttpTimeouts,
    ) -> Result<reqwest::ClientBuilder, RciError> {
        let parsed = reqwest::Url::parse(router.as_str()).map_err(|_error| RciError::Policy)?;
        let host = parsed.host_str().ok_or(RciError::Policy)?.to_owned();
        let port = parsed.port_or_known_default().ok_or(RciError::Policy)?;
        let resolved = spawn_blocking({
            let resolver_host = host.clone();
            move || {
                (resolver_host.as_str(), port)
                    .to_socket_addrs()
                    .map(Iterator::collect::<Vec<_>>)
            }
        })
        .await
        .map_err(|_join_error| RciError::Policy)?
        .map_err(|_resolve_error| RciError::Policy)?;
        self.client_builder_for_resolved(router, tls_mode, timeouts, &resolved)
    }

    /// Builds the no-redirect client after resolution and policy validation.
    ///
    /// # Errors
    ///
    /// Returns [`RciError::Policy`] when the TLS client configuration cannot be built.
    fn pinned_builder(
        host: &str,
        resolved: &[SocketAddr],
        tls_mode: &TlsMode,
        timeouts: HttpTimeouts,
    ) -> Result<reqwest::ClientBuilder, RciError> {
        let mut builder = Client::builder()
            .redirect(Policy::none())
            .connect_timeout(timeouts.connect)
            .read_timeout(timeouts.read)
            .resolve_to_addrs(host, resolved);
        if let TlsMode::PinSha256(fingerprint) = tls_mode {
            let provider = ring::default_provider();
            let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider.clone()))
                .with_safe_default_protocol_versions()
                .map_err(|_error| RciError::Policy)?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SpkiVerifier {
                    fingerprint: *fingerprint,
                    provider,
                }))
                .with_no_client_auth();
            builder = builder.use_preconfigured_tls(config);
        }
        Ok(builder)
    }

    /// Whether `address` is admitted for `host`.
    fn allows(&self, host: &str, resolved: IpAddr) -> bool {
        let address = resolved.to_canonical();
        if never_admitted(address) {
            return false;
        }
        if address.is_loopback() {
            return self.allow_loopback;
        }
        let embedded = embedded_ipv4(address);
        if embedded.is_some_and(|ipv4| ipv4.is_loopback()) && !self.allow_loopback {
            return false;
        }
        self.allowed_networks
            .iter()
            .any(|network| network.contains(address))
            || (is_global(address)
                && embedded.is_none_or(|ipv4| is_global(IpAddr::V4(ipv4)))
                && self.matches_suffix(host))
    }

    /// Whether `host` equals or is below one configured DNS suffix.
    fn matches_suffix(&self, host: &str) -> bool {
        let normalized_host = host.to_ascii_lowercase();
        self.allowed_suffixes.iter().any(|configured| {
            normalized_host == configured.as_str()
                || normalized_host
                    .strip_suffix(configured)
                    .is_some_and(|prefix| prefix.ends_with('.'))
        })
    }
}

/// Custom verifier for explicit leaf-SPKI pinning.
struct SpkiVerifier {
    /// Required SHA-256 SPKI digest.
    fingerprint: [u8; 32],
    /// Ring algorithms used to verify handshake signatures.
    provider: CryptoProvider,
}

impl fmt::Debug for SpkiVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpkiVerifier")
            .field("fingerprint", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for SpkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let (_remaining, certificate) =
            X509Certificate::from_der(end_entity.as_ref()).map_err(|_error| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let actual: [u8; 32] = Sha256::digest(certificate.public_key().raw).into();
        if bool::from(actual.ct_eq(&self.fingerprint)) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Whether `address` is a cloud metadata address, which no configuration admits.
#[inline]
#[must_use]
pub fn is_metadata_address(address: IpAddr) -> bool {
    METADATA_ADDRESSES.contains(&address.to_canonical())
}

/// Whether no outbound-policy setting can admit `address`.
#[inline]
#[must_use]
pub fn never_admitted(address: IpAddr) -> bool {
    let canonical_address = address.to_canonical();
    is_metadata_address(canonical_address)
        || is_unroutable(canonical_address)
        || is_forbidden_ipv6_form(canonical_address)
        || embedded_ipv4(canonical_address).is_some_and(|ipv4| {
            is_metadata_address(IpAddr::V4(ipv4)) || is_unroutable(IpAddr::V4(ipv4))
        })
}

/// Extracts an IPv4 address carried by a supported IPv6 transition form.
fn embedded_ipv4(address: IpAddr) -> Option<Ipv4Addr> {
    let IpAddr::V6(ipv6) = address else {
        return None;
    };
    let [first, second, third, fourth, fifth, sixth, seventh, eighth] = ipv6.segments();
    if [first, second, third, fourth, fifth, sixth] == [0x0064, 0xff9b, 0, 0, 0, 0]
        || [first, second, third, fourth, fifth, sixth] == [0, 0, 0, 0, 0xffff, 0]
        || ([first, second, third, fourth, fifth, sixth] == [0, 0, 0, 0, 0, 0]
            && !ipv6.is_unspecified()
            && !ipv6.is_loopback())
    {
        Some(Ipv4Addr::from(
            (u32::from(seventh) << 16) | u32::from(eighth),
        ))
    } else if first == 0x2002 {
        Some(Ipv4Addr::from((u32::from(second) << 16) | u32::from(third)))
    } else {
        None
    }
}

/// Identifies IPv6 transition forms that no outbound setting admits.
const fn is_forbidden_ipv6_form(address: IpAddr) -> bool {
    let IpAddr::V6(ipv6) = address else {
        return false;
    };
    let [first, second, third, _, _, _, _, _] = ipv6.segments();
    (first == 0x0064 && second == 0xff9b && third == 1) || (first == 0x2001 && second == 0)
}

/// Whether no configured outbound path may admit `address`.
const fn is_unroutable(address: IpAddr) -> bool {
    address.is_unspecified()
        || address.is_multicast()
        || matches!(address, IpAddr::V4(ipv4) if ipv4.is_broadcast())
}

/// Whether `address` is globally routable under the IANA special-purpose registries.
fn is_global(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            !matches!(
                octets,
                [0 | 10 | 127 | 224..=255, _, _, _]
                    | [100, 64..=127, _, _]
                    | [169, 254, _, _]
                    | [172, 16..=31, _, _]
                    | [192, 0, 0, 0..=8 | 11..=255]
                    | [192, 0, 2, _]
                    | [192, 88, 99, _]
                    | [192, 168, _, _]
                    | [198, 18..=19, _, _]
                    | [198, 51, 100, _]
                    | [203, 0, 113, _]
            )
        }
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            !ipv6.is_unspecified()
                && !ipv6.is_loopback()
                && !ipv6.is_multicast()
                && segments[0] & 0xfe00 != 0xfc00
                && segments[0] & 0xffc0 != 0xfe80
                && segments[0] & 0xffc0 != 0xfec0
                && segments[..2] != [0x2001, 0x0db8]
                && segments[..3] != [0x2001, 0x0002, 0]
                && segments[0] != 0x0100
                && !(segments[0] == 0x2001 && segments[1] & 0xfff0 == 0x0010)
                && !(segments[0] == 0x2001 && segments[1] & 0xfff0 == 0x0020)
                && !(segments[0] == 0x3fff && segments[1] <= 0x0fff)
                && segments[0] != 0x5f00
        }
    }
}

/// Constructs a known-valid default network.
const fn network(address: IpAddr, prefix_len: u8) -> AllowedNetwork {
    AllowedNetwork {
        address,
        prefix_len,
    }
}

/// Masks an address to `prefix_len` bits, returning a sentinel on family mismatch.
fn network_address(address: IpAddr, prefix_len: u8) -> IpAddr {
    match address {
        IpAddr::V4(value) if prefix_len <= 32 => {
            let host_bits = 32_u8.saturating_sub(prefix_len);
            let mask = u32::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(value) & mask))
        }
        IpAddr::V6(value) if prefix_len <= 128 => {
            let host_bits = 128_u8.saturating_sub(prefix_len);
            let mask = u128::MAX.checked_shl(u32::from(host_bits)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(value) & mask))
        }
        IpAddr::V4(_) | IpAddr::V6(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}
