//! The firmware tables name exactly the hardware-verified lines of the code.

use std::{fs, path::Path};

use kcc_rci::capabilities::HARDWARE_VERIFIED;

use super::markdown::root;

/// The tier column value of a hardware-verified line.
const VERIFIED: &str = "`hardware-verified`";

/// One firmware row: its `(major, minor)` line and its cells after the first.
fn rows(text: &str) -> Vec<((u16, u16), Vec<String>)> {
    text.lines()
        .filter_map(|line| {
            let mut cells = line.strip_prefix('|')?.split('|').map(str::trim);
            let first = cells.next()?;
            let numbers = first.split_whitespace().next()?;
            let (major, minor) = numbers.split_once('.')?;
            let line_id = (major.parse().ok()?, minor.parse().ok()?);
            Some((line_id, cells.map(str::to_owned).collect()))
        })
        .collect()
}

/// Checks the table at `path`; with `evidence`, each verified row needs a live-evidence cell.
fn check(path: &Path, evidence: bool) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut verified = Vec::new();
    for (line, cells) in rows(&text) {
        if cells.first().is_some_and(|tier| tier.starts_with(VERIFIED)) {
            verified.push(line);
            let live = cells.get(2).map_or("", String::as_str);
            if evidence && live.is_empty() {
                return Err(format!("{line:?} names no live evidence"));
            }
        }
    }
    verified.sort_unstable();
    let mut expected = HARDWARE_VERIFIED.to_vec();
    expected.sort_unstable();
    if verified == expected {
        Ok(())
    } else {
        Err(format!(
            "{}: hardware-verified lines {verified:?}, code says {expected:?}",
            path.display()
        ))
    }
}

#[test]
fn firmware_tables_match_hardware_verified() -> Result<(), String> {
    check(&root().join("docs/FIRMWARE.md"), true)?;
    check(&root().join("README.md"), false)
}
