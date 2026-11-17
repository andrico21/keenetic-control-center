//! Why the classifier gave a line its disposition, and the operator input a line depends
//! on, as types a caller matches exhaustively.

use core::fmt;

use serde::Deserialize;

/// Why a source line has its disposition: the reason key of the rule or engine branch
/// that decided it.
///
/// Every reason the classifier gives is a variant, so a caller's `match` names each one
/// and a new reason fails its build instead of reading as another. The key
/// ([`Reason::key`]) is the stable machine name in plans, reports and tool results.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[expect(
    clippy::exhaustive_enums,
    reason = "callers must match every reason; a new one has to break their build"
)]
pub enum Reason {
    /// No rule matched and the target's catalog has the command: copied as it is.
    #[serde(rename = "migration-reason-default-copy")]
    DefaultCopy,
    /// A setting holding a secret, copied as it is.
    #[serde(rename = "migration-reason-copy-secret")]
    CopySecret,
    /// A description that changes no behaviour, copied as it is.
    #[serde(rename = "migration-reason-non-critical-description")]
    NonCriticalDescription,
    /// A setting naming an object the maps rename.
    #[serde(rename = "migration-reason-remap-reference")]
    RemapReference,
    /// A router user's password hash bound to the source's realm.
    #[serde(rename = "migration-reason-password-realm")]
    PasswordRealm,
    /// A value that differs from the target's.
    #[serde(rename = "migration-reason-scalar-conflict")]
    ScalarConflict,
    /// A setting that needs a component the target lacks.
    #[serde(rename = "migration-reason-install-component")]
    InstallComponent,
    /// The source's LEDs.
    #[serde(rename = "migration-reason-hardware-led")]
    HardwareLed,
    /// The source's buttons.
    #[serde(rename = "migration-reason-hardware-button")]
    HardwareButton,
    /// The source's USB devices.
    #[serde(rename = "migration-reason-hardware-usb")]
    HardwareUsb,
    /// The source's radios.
    #[serde(rename = "migration-reason-hardware-radio")]
    HardwareRadio,
    /// The source's printers.
    #[serde(rename = "migration-reason-hardware-printer")]
    HardwarePrinter,
    /// A bridge member the target does not have.
    #[serde(rename = "migration-reason-hardware-interface")]
    HardwareInterface,
    /// The source's dynamic DNS name.
    #[serde(rename = "migration-reason-identity-ndns")]
    IdentityNdns,
    /// The source's cloud registration.
    #[serde(rename = "migration-reason-identity-cloud")]
    IdentityCloud,
    /// The source's certificates.
    #[serde(rename = "migration-reason-identity-certificate")]
    IdentityCertificate,
    /// The source's mesh Wi-Fi system identity.
    #[serde(rename = "migration-reason-identity-mws")]
    IdentityMws,
    /// The source's MAC addresses.
    #[serde(rename = "migration-reason-identity-mac")]
    IdentityMac,
    /// An agreement the source accepted; the target accepts its own.
    #[serde(rename = "migration-reason-preflight-agreement")]
    PreflightAgreement,
    /// A kernel tunable of the source's hardware.
    #[serde(rename = "migration-reason-kernel-tunable")]
    KernelTunable,
    /// The target's catalog has no such command.
    #[serde(rename = "migration-reason-unsupported-command")]
    UnsupportedCommand,
    /// A management change whose reconnect address the operator has not confirmed.
    #[serde(rename = "migration-reason-management-reconnect")]
    ManagementReconnect,
}

impl Reason {
    /// The reason's stable machine name, such as `migration-reason-copy-secret`.
    #[inline]
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::DefaultCopy => "migration-reason-default-copy",
            Self::CopySecret => "migration-reason-copy-secret",
            Self::NonCriticalDescription => "migration-reason-non-critical-description",
            Self::RemapReference => "migration-reason-remap-reference",
            Self::PasswordRealm => "migration-reason-password-realm",
            Self::ScalarConflict => "migration-reason-scalar-conflict",
            Self::InstallComponent => "migration-reason-install-component",
            Self::HardwareLed => "migration-reason-hardware-led",
            Self::HardwareButton => "migration-reason-hardware-button",
            Self::HardwareUsb => "migration-reason-hardware-usb",
            Self::HardwareRadio => "migration-reason-hardware-radio",
            Self::HardwarePrinter => "migration-reason-hardware-printer",
            Self::HardwareInterface => "migration-reason-hardware-interface",
            Self::IdentityNdns => "migration-reason-identity-ndns",
            Self::IdentityCloud => "migration-reason-identity-cloud",
            Self::IdentityCertificate => "migration-reason-identity-certificate",
            Self::IdentityMws => "migration-reason-identity-mws",
            Self::IdentityMac => "migration-reason-identity-mac",
            Self::PreflightAgreement => "migration-reason-preflight-agreement",
            Self::KernelTunable => "migration-reason-kernel-tunable",
            Self::UnsupportedCommand => "migration-reason-unsupported-command",
            Self::ManagementReconnect => "migration-reason-management-reconnect",
        }
    }
}

impl fmt::Display for Reason {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.key())
    }
}

/// The operator input a classified line depends on.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::exhaustive_enums,
    reason = "callers must match every input; a new one has to break their build"
)]
pub enum NeededInput {
    /// Consent to install `component` on the target first.
    Install {
        /// The component's name, such as `wireguard`.
        component: String,
    },
    /// A new password for router user `user`, whose hash is bound to the source's realm.
    Password {
        /// The router user.
        user: String,
    },
    /// Confirmation of the address to reach the router at after a management change.
    ReconnectUrl,
}

impl fmt::Display for NeededInput {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Install { component } => write!(f, "install {component}"),
            Self::Password { user } => write!(f, "new password for {user}"),
            Self::ReconnectUrl => f.write_str("confirm reconnect URL"),
        }
    }
}
