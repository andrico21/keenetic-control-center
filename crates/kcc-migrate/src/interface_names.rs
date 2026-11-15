//! Keenetic interface-name classification used by migration safety checks.

/// Recognizes source interface names that denote router hardware.
pub(crate) fn is_physical(name: &str) -> bool {
    name == "ISP"
        || name.starts_with("FastEthernet")
        || name.starts_with("Usb")
        || name.starts_with("Ethernet")
        || physical_gigabit_ethernet(name)
        || physical_wifi(name)
}

/// Recognizes a base Gigabit Ethernet port while excluding logical suffixes.
fn physical_gigabit_ethernet(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("GigabitEthernet") else {
        return false;
    };
    let mut parts = suffix.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(group), Some(port), None)
            if group.chars().all(|character| character.is_ascii_digit())
                && port.chars().all(|character| character.is_ascii_digit())
    )
}

/// Recognizes Wi-Fi radio and access-point hardware names.
fn physical_wifi(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("WifiMaster") else {
        return false;
    };
    let mut parts = suffix.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(radio), None, None) => radio.chars().all(|character| character.is_ascii_digit()),
        (Some(radio), Some(point), None) => {
            radio.chars().all(|character| character.is_ascii_digit())
                && point.strip_prefix("AccessPoint").is_some_and(|number| {
                    number.chars().all(|character| character.is_ascii_digit())
                })
        }
        (Some(_) | None, Some(_) | None, Some(_) | None) => false,
    }
}

#[cfg(test)]
#[expect(clippy::missing_panics_doc, reason = "test contracts")]
mod tests {
    use super::is_physical;

    /// Names are classified by their documented shapes.
    ///
    /// The hardware prefixes, a base `GigabitEthernet<group>/<port>` port, a `WifiMaster<n>`
    /// radio and its `AccessPoint<m>` are physical; other names, non-numeric parts and extra
    /// path segments are logical.
    #[test]
    fn names_follow_the_documented_shapes() {
        for (name, physical) in [
            ("ISP", true),
            ("FastEthernet0/1", true),
            ("Usb0", true),
            ("Ethernet0", true),
            ("GigabitEthernet0/4", true),
            ("WifiMaster1", true),
            ("WifiMaster0/AccessPoint1", true),
            ("ISP0", false),
            ("Bridge0", false),
            ("GigabitEthernet1", false),
            ("GigabitEthernet0/Vlan2", false),
            ("GigabitEthernet0/4/1", false),
            ("WifiMasterA", false),
            ("WifiMaster0/AccessPointA", false),
            ("WifiMaster0/AccessPoint0/1", false),
        ] {
            assert_eq!(is_physical(name), physical, "{name}");
        }
    }
}
