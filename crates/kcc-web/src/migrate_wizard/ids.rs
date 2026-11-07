//! Migration ids: the directory name of each migration, unique and path-safe. The
//! presets' apply runs and saved presets take ids of the same form.

use rand::{TryRng as _, rngs::SysRng};

/// Whether `id` can be a migration id: what [`new_id`] makes.
pub(crate) fn is_id(id: &str) -> bool {
    (12..=40).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f' | b'-'))
}

/// A new id started at `now`, or `None` when the operating system's random generator
/// fails.
pub(crate) fn fresh_id(now: u64) -> Option<String> {
    let mut random = [0_u8; 8];
    SysRng.try_fill_bytes(&mut random).ok()?;
    Some(new_id(now, random))
}

/// A new migration id: the start time and eight random bytes.
pub(crate) fn new_id(now: u64, random: [u8; 8]) -> String {
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .concat();
    format!("{now}-{suffix}")
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{is_id, new_id};

    #[test]
    fn ids_are_path_safe_and_checked() {
        let id = new_id(1_700_000_000, [0xab, 1, 2, 3, 4, 5, 6, 0xff]);
        assert_eq!(id, "1700000000-ab010203040506ff", "time and random hex");
        assert!(is_id(&id), "accepted");
        for bad in [
            "",
            "../etc",
            "1700000000-AB010203",
            "1700000000/ab01020304",
            "x",
        ] {
            assert!(!is_id(bad), "{bad}");
        }
    }
}
