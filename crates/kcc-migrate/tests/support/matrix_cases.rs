//! Source and target definitions of the cross-model migration matrix.

use core::fmt::Write as _;

use kcc_testkit::model::{Firmware, Model, Profile, UnsupportedProfile};

/// Saved 4.3-era Giga startup configuration used as a file source.
pub(crate) const GIGA_43_FILE: &str = include_str!("../fixtures/giga-4.3-startup-config.txt");

/// One migration source of the matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    /// Live `KN-1010` on 5.1.
    Giga51,
    /// Live `KN-1811` on 5.1.
    Ultra51,
    /// Saved 4.3-era Giga startup configuration.
    Giga43File,
    /// Live `KN-1811` on 5.1 with a WireGuard interface and an extra segment.
    ///
    /// Policy, DHCP-pool and WireGuard key lines are absent: the applier cannot replay them
    /// yet (catalog CLI validation rejects context leaf commands; see the notepad issue).
    Ultra51Vpn,
}

impl Source {
    /// Every source in report order.
    pub(crate) const ALL: [Self; 4] = [
        Self::Giga51,
        Self::Ultra51,
        Self::Giga43File,
        Self::Ultra51Vpn,
    ];

    /// Stable snapshot name component.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Giga51 => "KN-1010-5.1",
            Self::Ultra51 => "KN-1811-5.1",
            Self::Giga43File => "giga-4.3-file",
            Self::Ultra51Vpn => "KN-1811-5.1-vpn",
        }
    }

    /// The simulated source router, or `None` for the saved file.
    pub(crate) const fn profile(self) -> Option<Profile> {
        match self {
            Self::Giga51 => Some(Profile::latest(Model::Kn1010)),
            Self::Ultra51 | Self::Ultra51Vpn => Some(Profile::latest(Model::Kn1811)),
            Self::Giga43File => None,
        }
    }

    /// Full-path configuration lines applied to the live source before it is saved.
    ///
    /// Secrets are derived at run time and never appear as literals.
    pub(crate) fn seed_lines(self) -> Vec<String> {
        let mut lines = vec![
            "interface Bridge1 description Guest".to_owned(),
            "interface Bridge1 ip address 198.51.100.65 255.255.255.192".to_owned(),
            "ip host nas.home 198.51.100.10".to_owned(),
            "known host printer 02:00:00:00:00:10".to_owned(),
            format!("user operator password md5 {}", dummy_hex("operator")),
        ];
        if self == Self::Ultra51Vpn {
            lines.extend([
                "interface Bridge2 description IoT".to_owned(),
                "interface Bridge2 ip address 198.51.100.129 255.255.255.192".to_owned(),
                "interface Wireguard0 description Office".to_owned(),
                "interface Wireguard0 ip address 203.0.113.2 255.255.255.0".to_owned(),
            ]);
        }
        lines
    }
}

/// One migration target of the matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Target {
    /// `KN-1811` on 5.1.
    Ultra51,
    /// `KN-1811` on 4.3.9 LTS (documentation tier).
    Ultra43,
    /// `KN-3810` on 5.1.
    Hopper51,
    /// `NC-3013` on 5.1.
    Speedster51,
}

impl Target {
    /// Every target in report order.
    pub(crate) const ALL: [Self; 4] = [
        Self::Ultra51,
        Self::Ultra43,
        Self::Hopper51,
        Self::Speedster51,
    ];

    /// Stable snapshot name component.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Ultra51 => "KN-1811-5.1",
            Self::Ultra43 => "KN-1811-4.3.9",
            Self::Hopper51 => "KN-3810-5.1",
            Self::Speedster51 => "NC-3013-5.1",
        }
    }

    /// The simulated target router.
    ///
    /// # Errors
    /// Returns a profile the simulator does not ship.
    pub(crate) fn profile(self) -> Result<Profile, UnsupportedProfile> {
        match self {
            Self::Ultra51 => Ok(Profile::latest(Model::Kn1811)),
            Self::Ultra43 => Profile::new(Model::Kn1811, Firmware::V4_3),
            Self::Hopper51 => Ok(Profile::latest(Model::Kn3810)),
            Self::Speedster51 => Ok(Profile::latest(Model::Nc3013)),
        }
    }

    /// Whether the target firmware is documentation-derived and needs acknowledgement.
    pub(crate) const fn documentation_tier(self) -> bool {
        matches!(self, Self::Ultra43)
    }
}

/// Pair expectation derived from firmware ordering, not from observed behaviour.
pub(crate) const fn target_is_older(source: Source, target: Target) -> bool {
    matches!(target, Target::Ultra43) && !matches!(source, Source::Giga43File)
}

/// Whether both ends are the same hardware model.
pub(crate) const fn same_model(source: Source, target: Target) -> bool {
    matches!(
        (source, target),
        (
            Source::Ultra51 | Source::Ultra51Vpn,
            Target::Ultra51 | Target::Ultra43
        )
    )
}

/// Builds a 32-character lowercase hex dummy from a label.
fn dummy_hex(label: &str) -> String {
    let mut text = String::with_capacity(32);
    for byte in label.bytes().cycle().take(16) {
        let _ignored = write!(text, "{byte:02x}");
    }
    text
}
