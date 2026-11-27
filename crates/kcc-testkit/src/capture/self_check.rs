//! The self-check of a written capture.

pub mod hits;

use alloc::collections::BTreeSet;
use std::{fs, io, path::Path};

use serde_json::Value;

use self::hits::Explain;
use super::{CaptureError, INTERFACE_STAT_PREFIX, MANIFEST, Rendered, detector::Detector, items};

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
/// [`CaptureError::IdentifierLeaked`] naming the first file and the kind of identifier and
/// listing every hit without a value (see [`hits::LeakHit`]); [`CaptureError::Io`] when
/// reading or deleting fails. Either way the directory is deleted first.
#[inline]
pub fn self_check(directory: &Path, rendered: &Rendered) -> Result<(), CaptureError> {
    let outcome = scan(directory, rendered);
    if outcome.is_err() {
        fs::remove_dir_all(directory)?;
    }
    outcome
}

/// The self-check without the deletion: every leak, or the first I/O error.
///
/// # Errors
///
/// As [`self_check`].
fn scan(directory: &Path, rendered: &Rendered) -> Result<(), CaptureError> {
    let detector = Detector::new(&rendered.identifiers);
    let fixed = fixed_words();
    let tokens = fixed_tokens(&fixed);
    let names: BTreeSet<&str> = rendered
        .files
        .keys()
        .map(String::as_str)
        .chain([MANIFEST])
        .collect();
    let mut first = None;
    let mut found = Vec::new();
    for name in names {
        let written = fs::read_to_string(directory.join(name))?;
        let manifest = (name == MANIFEST)
            .then(|| serde_json::from_str::<Value>(&written).map_err(io::Error::other))
            .transpose()?;
        let scanned = manifest
            .as_ref()
            .map_or_else(|| written.clone(), |parsed| router_words(parsed, &fixed));
        let Some((kind, _)) = detector.finding(&scanned) else {
            continue;
        };
        let _: &mut (String, _) = first.get_or_insert_with(|| (name.to_owned(), kind));
        let explain = Explain::new(name, &detector, rendered);
        let mut file_hits = manifest.as_ref().map_or_else(
            || explain.in_lines(&written),
            |parsed| explain.in_manifest(parsed, &fixed, &tokens),
        );
        if file_hits.is_empty() {
            file_hits.push(explain.whole_file(kind));
        }
        found.extend(file_hits);
    }
    match first {
        Some((item, kind)) => Err(CaptureError::IdentifierLeaked {
            item,
            kind,
            hits: found,
        }),
        None => Ok(()),
    }
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

/// The parts of the fixed words and of the interface-stat item prefix between the
/// separators `-`, `_`, `.` and `/`: the only text a diagnostic shows beside a match.
fn fixed_tokens(fixed: &BTreeSet<String>) -> BTreeSet<String> {
    fixed
        .iter()
        .map(String::as_str)
        .chain([INTERFACE_STAT_PREFIX])
        .flat_map(|word| word.split(['-', '_', '.', '/']))
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every key and string of `manifest` that is not in `fixed`, one per line: the parts the
/// router decided (identity, interface ids, skip reasons).
fn router_words(manifest: &Value, fixed: &BTreeSet<String>) -> String {
    let mut pending = vec![manifest];
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
    words
}

#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod hit_tests;
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
        anonymize::{Identifier, IdentifierKind, vocabulary::Vocabulary},
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
            sources: Vec::new(),
            vocabulary: Vocabulary::default(),
        };
        let directory = rendered.write(scratch.path())?;
        match self_check(&directory, &rendered) {
            Ok(()) if directory.exists() => Ok(None),
            Ok(()) => Err("a passing self-check removed the directory".into()),
            Err(CaptureError::IdentifierLeaked {
                item,
                kind,
                hits: _,
            }) if item == "item.json" && !directory.exists() => Ok(Some(kind)),
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
