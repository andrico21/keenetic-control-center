//! Secret-free WAN response models.

use alloc::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Supported WAN connection kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ConnectionKind {
    /// Ethernet IP connection using DHCP or a static address.
    Ipoe,
    /// PPP over Ethernet.
    Pppoe,
    /// Layer 2 Tunneling Protocol.
    L2tp,
    /// Point-to-Point Tunneling Protocol.
    Pptp,
}

/// Tolerant WAN connection view that exposes credential presence only.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[non_exhaustive]
pub struct Connection {
    /// Stable interface identifier.
    pub id: Option<String>,
    /// Supported connection kind.
    pub kind: Option<ConnectionKind>,
    /// Administrative state.
    pub state: Option<String>,
    /// Current address.
    pub address: Option<String>,
    /// Whether DHCP addressing is configured.
    pub dhcp: Option<bool>,
    /// Underlying interface for tunneled connections.
    pub via: Option<String>,
    /// Global-routing priority.
    pub priority: Option<i64>,
    /// Configured MTU.
    pub mtu: Option<u16>,
    /// Whether a default route is requested through IPCP.
    pub default_route: Option<bool>,
    /// Whether an authentication identity is stored.
    pub identity_present: bool,
    /// Whether an authentication password is stored.
    pub password_present: bool,
    /// Unmodelled non-authentication router fields.
    pub extra: BTreeMap<String, Value>,
}

/// Internal wire model retaining authentication only until presence is projected.
#[derive(Default, Deserialize)]
#[serde(default)]
struct WireConnection {
    /// Stable interface identifier.
    id: Option<String>,
    /// Raw router interface type.
    #[serde(rename = "type")]
    kind: Option<String>,
    /// Administrative state.
    state: Option<String>,
    /// Current address.
    address: Option<String>,
    /// DHCP marker.
    dhcp: Option<bool>,
    /// Underlying interface.
    via: Option<String>,
    /// Global-routing priority.
    priority: Option<i64>,
    /// Configured MTU.
    mtu: Option<u16>,
    /// IPCP default-route marker.
    #[serde(rename = "default-route")]
    default_route: Option<bool>,
    /// Temporary authentication wire object.
    authentication: Option<Authentication>,
    /// Unmodelled non-authentication fields.
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

/// Authentication wire fields used only to compute presence booleans.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Authentication {
    /// Identity value, discarded immediately after decoding.
    identity: Option<Value>,
    /// Password value, discarded immediately after decoding.
    password: Option<Value>,
}

impl<'de> Deserialize<'de> for Connection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireConnection::deserialize(deserializer)?;
        let kind = wire.kind.as_deref().and_then(connection_kind);
        let (identity_present, password_present) =
            wire.authentication
                .map_or((false, false), |authentication| {
                    (
                        authentication.identity.is_some(),
                        authentication.password.is_some(),
                    )
                });
        Ok(Self {
            id: wire.id,
            kind,
            state: wire.state,
            address: wire.address,
            dhcp: wire.dhcp,
            via: wire.via,
            priority: wire.priority,
            mtu: wire.mtu,
            default_route: wire.default_route,
            identity_present,
            password_present,
            extra: wire.extra,
        })
    }
}

/// Maps router interface types to supported WAN kinds.
fn connection_kind(kind: &str) -> Option<ConnectionKind> {
    match kind.to_ascii_lowercase().as_str() {
        "gigabitethernet" | "ethernet" | "ipoe" => Some(ConnectionKind::Ipoe),
        "pppoe" => Some(ConnectionKind::Pppoe),
        "l2tp" => Some(ConnectionKind::L2tp),
        "pptp" => Some(ConnectionKind::Pptp),
        _ => None,
    }
}
