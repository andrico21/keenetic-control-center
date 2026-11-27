//! MAC spellings other than the colon and hyphen forms: Cisco-style dotted
//! (`0200.0000.0001`) and bare hex (`020000000001`).

/// Parses twelve hex digits (any case) into bytes.
pub(super) fn parse_bare(text: &str) -> Option<[u8; 6]> {
    if text.len() != 12 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let [_, _, mac @ ..] = u64::from_str_radix(text, 16).ok()?.to_be_bytes();
    Some(mac)
}

/// Parses three dot-separated groups of four hex digits (any case) into bytes.
pub(super) fn parse_dotted(text: &str) -> Option<[u8; 6]> {
    let groups: Vec<&str> = text.split('.').collect();
    match groups.as_slice() {
        [first, second, third] if [first, second, third].iter().all(|group| group.len() == 4) => {
            parse_bare(&groups.concat())
        }
        _ => None,
    }
}

/// The dotted spelling of the replacement MAC `02:00:00:<suffix>`.
pub(super) fn dotted([first, second, third]: [u8; 3]) -> String {
    format!("0200.00{first:02x}.{second:02x}{third:02x}")
}

/// The bare spelling of the replacement MAC `02:00:00:<suffix>`.
pub(super) fn bare([first, second, third]: [u8; 3]) -> String {
    format!("020000{first:02x}{second:02x}{third:02x}")
}

/// The four spellings the self-check looks for of a MAC given in colon spelling.
///
/// Colon, hyphen, dotted and bare, all lowercase.
pub(crate) fn spellings(mac: &str) -> [String; 4] {
    let colon = mac.to_ascii_lowercase();
    let bare: String = colon
        .chars()
        .filter(|character| *character != ':')
        .collect();
    let dotted = [bare.get(..4), bare.get(4..8), bare.get(8..)]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(".");
    [colon.replace(':', "-"), dotted, bare, colon]
}
