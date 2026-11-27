//! The self-check of a written capture.

use alloc::collections::BTreeSet;
use core::net::{IpAddr, Ipv4Addr};
use std::{fs, io, path::Path};

use serde_json::Value;

use super::{CaptureError, MANIFEST, Rendered, items};
use crate::anonymize::{
    Identifier, IdentifierKind,
    fold::{contains_folded, fold, percent_decoded},
    ipv4_forms, mac_forms,
    runs::{self, has_foreign_ipv6},
};

/// Scans every file this run wrote into `directory` (`rendered`'s files and the manifest)
/// for every identifier; on a hit or any error it deletes `directory`.
///
/// Each file is scanned as written and percent-decoded, with Unicode case ignored: a value
/// of six or more characters anywhere, a shorter one as a whole word, the rule the
/// anonymizer replaces by; a MAC in its colon, hyphen, dotted and bare spelling; a learned
/// IPv4 address also dashed, underscored or zero-padded; a learned IPv6 address's `/48`
/// also inside any other IPv6 address. Any global or unique-local IPv6 address outside
/// `2001:db8::/32`, and any link-local or multicast address that may carry one, is a leak
/// too, learned or not. Of the manifest only the words the router decided are scanned, not
/// the fixed item names.
///
/// # Errors
///
/// [`CaptureError::IdentifierLeaked`] naming the file and the kind of identifier, never the
/// value; [`CaptureError::Io`] when reading or deleting fails. Either way the directory is
/// deleted first.
#[inline]
pub fn self_check(directory: &Path, rendered: &Rendered) -> Result<(), CaptureError> {
    let outcome = scan(directory, rendered);
    if outcome.is_err() {
        fs::remove_dir_all(directory)?;
    }
    outcome
}

/// The self-check without the deletion: the first leak, or the first I/O error.
///
/// # Errors
///
/// As [`self_check`].
fn scan(directory: &Path, rendered: &Rendered) -> Result<(), CaptureError> {
    let needles: Vec<(String, IdentifierKind)> = rendered
        .identifiers
        .iter()
        .flat_map(|identifier| {
            let spellings = if identifier.kind == IdentifierKind::Mac {
                mac_forms::spellings(&identifier.value).to_vec()
            } else {
                vec![fold(&identifier.value)]
            };
            spellings
                .into_iter()
                .map(|needle| (needle, identifier.kind))
        })
        .collect();
    let (ipv4, prefixes) = learned_addresses(&rendered.identifiers);
    let fixed = fixed_words();
    let names: BTreeSet<&str> = rendered
        .files
        .keys()
        .map(String::as_str)
        .chain([MANIFEST])
        .collect();
    for name in names {
        let written = fs::read_to_string(directory.join(name))?;
        let text = if name == MANIFEST {
            router_words(&written, &fixed)?
        } else {
            written
        };
        let decoded = text
            .contains(['%', '+'])
            .then(|| fold(&percent_decoded(&text)));
        let haystacks = [Some(fold(&text)), decoded];
        let leaked = needles
            .iter()
            .find(|(needle, _)| {
                haystacks
                    .iter()
                    .flatten()
                    .any(|haystack| contains_folded(haystack, needle))
            })
            .map(|(_, kind)| *kind)
            .or_else(|| {
                haystacks
                    .iter()
                    .flatten()
                    .any(|haystack| {
                        has_foreign_ipv6(haystack)
                            || ipv4_forms::holds_learned(haystack, &ipv4)
                            || runs::holds_prefix(haystack, &prefixes)
                    })
                    .then_some(IdentifierKind::Address)
            });
        if let Some(kind) = leaked {
            return Err(CaptureError::IdentifierLeaked {
                item: name.to_owned(),
                kind,
            });
        }
    }
    Ok(())
}

/// The learned IPv4 addresses and the `/48` prefixes of the learned IPv6 addresses among
/// `identifiers`, which the self-check also looks for in other spellings.
fn learned_addresses(identifiers: &[Identifier]) -> (BTreeSet<Ipv4Addr>, BTreeSet<[u16; 3]>) {
    let mut ipv4 = BTreeSet::new();
    let mut prefixes = BTreeSet::new();
    for identifier in identifiers {
        match identifier.value.parse::<IpAddr>() {
            Ok(IpAddr::V4(address)) => {
                let _: bool = ipv4.insert(address);
            }
            Ok(IpAddr::V6(address)) => prefixes.extend(runs::learned_prefixes(address)),
            Err(_) => {}
        }
    }
    (ipv4, prefixes)
}

/// The words of the manifest that never come from the router: its keys and the name and
/// file name of every fixed item.
fn fixed_words() -> BTreeSet<String> {
    let keys = ["hw_id", "title", "items", "name", "file", "skipped"].map(str::to_owned);
    items()
        .into_iter()
        .flat_map(|item| {
            ["json", "txt"]
                .map(|extension| format!("{}.{extension}", item.name))
                .into_iter()
                .chain([item.name])
        })
        .chain(keys)
        .collect()
}

/// Every key and string of the manifest `text` that is not in `fixed`, one per line: the
/// parts the router decided (identity, interface ids, skip reasons).
///
/// # Errors
///
/// [`io::ErrorKind::InvalidData`] when the manifest is not JSON.
fn router_words(text: &str, fixed: &BTreeSet<String>) -> io::Result<String> {
    let manifest: Value = serde_json::from_str(text).map_err(io::Error::other)?;
    let mut pending = vec![&manifest];
    let mut words = String::new();
    let mut push = |word: &str| {
        if !fixed.contains(word) {
            words.push_str(word);
            words.push('\n');
        }
    };
    while let Some(value) = pending.pop() {
        match value {
            Value::Object(object) => {
                for (key, member) in object {
                    push(key);
                    pending.push(member);
                }
            }
            Value::Array(members) => pending.extend(members),
            Value::String(word) => push(word),
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(words)
}

#[cfg(test)]
mod render_tests;
#[cfg(test)]
mod spelling_tests;

#[cfg(test)]
mod tests {
    //! Matching rules of the self-check. Foreign MACs are assembled at run time so this
    //! file passes the repository secret scanner; messages never carry a planted value.

    use core::error::Error;

    use serde_json::json;
    use tempfile::TempDir;

    use super::self_check;
    use crate::{
        anonymize::{Identifier, IdentifierKind},
        capture::{CaptureError, Rendered},
    };

    /// Test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// An identifier of `kind`.
    pub(super) fn identifier(value: &str, kind: IdentifierKind) -> Identifier {
        Identifier {
            value: value.to_owned(),
            kind,
        }
    }

    /// Writes `content` as the only file of a fresh capture directory and self-checks it:
    /// `Some(kind)` on a leak (the directory is gone), `None` when it passes (it stays).
    ///
    /// # Errors
    ///
    /// Setup I/O errors, or a self-check error other than a leak.
    pub(super) fn leak_in(
        content: &str,
        identifiers: &[Identifier],
    ) -> Result<Option<IdentifierKind>, Box<dyn Error>> {
        let scratch = TempDir::new()?;
        let rendered = Rendered {
            directory: "capture".to_owned(),
            files: [("item.json".to_owned(), content.to_owned())].into(),
            manifest: json!({"items": [{"name": "item", "file": "item.json"}]}),
            identifiers: identifiers.to_vec(),
        };
        let directory = rendered.write(scratch.path())?;
        match self_check(&directory, &rendered) {
            Ok(()) if directory.exists() => Ok(None),
            Ok(()) => Err("a passing self-check removed the directory".into()),
            Err(CaptureError::IdentifierLeaked { item, kind })
                if item == "item.json" && !directory.exists() =>
            {
                Ok(Some(kind))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Case variants, values glued to word characters and non-ASCII values are found; a
    /// short value only as a whole word (todo 4).
    ///
    /// # Errors
    ///
    /// Setup I/O errors.
    ///
    /// # Panics
    ///
    /// Panics when a variant passes or an ordinary word fails.
    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    fn case_variants_glued_and_non_ascii_values_are_found() -> TestResult {
        let identifiers = [
            identifier("PLANTED-HOST-7", IdentifierKind::Host),
            identifier(
                "\u{414}\u{43e}\u{43c}\u{430}\u{448}\u{43d}\u{438}\u{439}",
                IdentifierKind::Host,
            ),
            identifier("Mama", IdentifierKind::Ssid),
        ];
        let leaking = [
            ("glued underscore", "lease planted-host-7_laptop"),
            ("glued letter", "xplanted-host-7"),
            ("glued hyphen", "Planted-Host-7-pc"),
            (
                "uppercase Cyrillic",
                "\u{43a}\u{43b}\u{438}\u{435}\u{43d}\u{442} \u{414}\u{41e}\u{41c}\u{410}\u{428}\u{41d}\u{418}\u{419}",
            ),
            (
                "Cyrillic glued",
                "\u{434}\u{43e}\u{43c}\u{430}\u{448}\u{43d}\u{438}\u{439}\u{43f}\u{43a}",
            ),
            ("short word", "joined MAMA."),
        ];
        for (case, content) in leaking {
            assert!(leak_in(content, &identifiers)?.is_some(), "{case} passed");
        }
        for (case, content) in [
            ("short inside a word", "mamaliga"),
            ("short glued", "host-mama"),
        ] {
            assert_eq!(leak_in(content, &identifiers)?, None, "{case} failed");
        }
        Ok(())
    }

    /// A learned MAC is found in colon, hyphen, dotted and bare spelling, any case (todo 4).
    ///
    /// # Errors
    ///
    /// Setup I/O errors.
    ///
    /// # Panics
    ///
    /// Panics when a spelling passes.
    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    fn learned_macs_are_found_in_every_spelling() -> TestResult {
        let mac = [identifier(
            &format!("a4:b1:c2:{}:e4:f5", "d3"),
            IdentifierKind::Mac,
        )];
        for (case, content) in [
            ("colon", format!("A4:B1:C2:{}:E4:F5", "D3")),
            ("hyphen", format!("a4-b1-c2-{}-e4-f5", "d3")),
            ("dotted", format!("mac a4b1.C2D3.{}", "e4f5")),
            ("bare", format!("mac=A4B1C2D3{}", "E4F5")),
        ] {
            assert_eq!(
                leak_in(&content, &mac)?,
                Some(IdentifierKind::Mac),
                "{case} spelling passed"
            );
        }
        Ok(())
    }

    /// A learned name written percent-encoded is found (todo 4).
    ///
    /// # Errors
    ///
    /// Setup I/O errors.
    ///
    /// # Panics
    ///
    /// Panics when an encoded name passes.
    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
    fn percent_encoded_names_are_found() -> TestResult {
        let name = [identifier("Planted Phone", IdentifierKind::Host)];
        for (case, content) in [
            ("space", "GET /x?n=Planted%20Phone&y=1"),
            ("plus", "n=planted+phone"),
            ("every byte", "%50%6c%61%6E%74%65%64%20%50%68%6f%6e%65"),
        ] {
            assert_eq!(
                leak_in(content, &name)?,
                Some(IdentifierKind::Host),
                "{case} encoding passed"
            );
        }
        let cyrillic = [identifier(
            "\u{414}\u{43e}\u{43c}\u{430}\u{448}\u{43d}\u{438}\u{439}",
            IdentifierKind::Host,
        )];
        assert_eq!(
            leak_in(
                "n=%D0%94%D0%BE%D0%BC%D0%B0%D1%88%D0%BD%D0%B8%D0%B9",
                &cyrillic
            )?,
            Some(IdentifierKind::Host),
            "encoded UTF-8 passed"
        );
        Ok(())
    }
}
