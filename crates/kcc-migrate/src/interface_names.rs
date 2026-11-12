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
