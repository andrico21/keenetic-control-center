//! The id a new router gets from its display name when none is typed.

extern crate alloc;

use alloc::collections::BTreeSet;

/// Most characters of a router id ([`super::address::is_slug`]).
const MAX_ID: usize = 32;

/// The id derived from the display name `name` that `taken` does not hold.
///
/// ASCII letters (lowercased) and digits are kept, every run of other characters becomes
/// one `-`, and the result is cut to 32 characters without a trailing `-`. A name that
/// leaves nothing gets `router-<n>` with the smallest free `n` from 1; a taken result
/// gets `-2`, `-3`, ..., cut so the whole id stays within 32 characters.
pub(crate) fn derived_id(name: &str, taken: &BTreeSet<String>) -> String {
    let base = slug(name);
    if base.is_empty() {
        return first_free(taken, 1, |number| format!("router-{number}"));
    }
    if !taken.contains(&base) {
        return base;
    }
    first_free(taken, 2, |number| {
        let suffix = format!("-{number}");
        format!(
            "{}{suffix}",
            cut(&base, MAX_ID.saturating_sub(suffix.len()))
        )
    })
}

/// `name` as lowercase ASCII letters and digits joined by single hyphens, at most
/// [`MAX_ID`] characters.
fn slug(name: &str) -> String {
    let mut slug = String::with_capacity(MAX_ID);
    let mut gap = false;
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            if gap && !slug.is_empty() {
                slug.push('-');
            }
            gap = false;
            slug.push(character.to_ascii_lowercase());
        } else {
            gap = true;
        }
    }
    cut(&slug, MAX_ID)
}

/// The first `room` characters of the ASCII `slug`, without a trailing hyphen.
fn cut(slug: &str, room: usize) -> String {
    slug.get(..room)
        .unwrap_or(slug)
        .trim_end_matches('-')
        .to_owned()
}

/// The first of `candidate(start)`, `candidate(start + 1)`, ... that `taken` does not
/// hold. The candidates are distinct, so one of the first `taken.len() + 1` is free.
fn first_free(
    taken: &BTreeSet<String>,
    start: usize,
    candidate: impl Fn(usize) -> String,
) -> String {
    let last = start.saturating_add(taken.len());
    (start..last)
        .map(&candidate)
        .find(|id| !taken.contains(id))
        .unwrap_or_else(|| candidate(last))
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test assertions are not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::collections::BTreeSet;

    use super::derived_id;
    use crate::router_form::address::is_slug;

    /// A synthetic Cyrillic name.
    const CYRILLIC: &str = "\u{414}\u{43e}\u{43c}\u{430}\u{448}\u{43d}\u{438}\u{439} \u{440}\u{43e}\u{443}\u{442}\u{435}\u{440}";

    /// The set of `ids`.
    fn taken(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|&id| id.to_owned()).collect()
    }

    /// Todo 11: letters and digits are kept in lowercase, every other run becomes one
    /// hyphen, and no hyphen leads or trails.
    #[test]
    fn a_name_becomes_a_lowercase_slug() {
        for (name, id) in [
            ("Home Office", "home-office"),
            ("  Home   Office!! ", "home-office"),
            ("LAB 2", "lab-2"),
            ("--a__b..c--", "a-b-c"),
            ("Caf\u{e9} Bar", "caf-bar"),
        ] {
            assert_eq!(derived_id(name, &taken(&[])), id, "{name}");
        }
    }

    /// Todo 11: a name without ASCII letters or digits gets the smallest free
    /// `router-<n>`.
    #[test]
    fn a_name_without_ascii_letters_gets_router_n() {
        for name in ["", "!!! ???", CYRILLIC] {
            assert_eq!(derived_id(name, &taken(&[])), "router-1", "{name:?}");
        }
        assert_eq!(
            derived_id(CYRILLIC, &taken(&["router-1", "router-3"])),
            "router-2",
            "skips taken ids"
        );
        assert_eq!(
            derived_id(CYRILLIC, &taken(&["router-1", "router-2"])),
            "router-3",
            "the next free one"
        );
    }

    /// Todo 11: a long name is cut to 32 characters without a trailing hyphen.
    #[test]
    fn a_long_name_is_cut_to_32_characters() {
        let long = "a".repeat(40);
        assert_eq!(derived_id(&long, &taken(&[])), "a".repeat(32), "40 letters");
        let hyphen_at_the_cut = format!("{} b", "a".repeat(31));
        assert_eq!(
            derived_id(&hyphen_at_the_cut, &taken(&[])),
            "a".repeat(31),
            "no trailing hyphen after the cut"
        );
        let exact = format!("{} {}", "a".repeat(15), "b".repeat(16));
        assert_eq!(
            derived_id(&exact, &taken(&[])),
            format!("{}-{}", "a".repeat(15), "b".repeat(16)),
            "32 characters fit"
        );
    }

    /// Todo 11: a taken id gets `-2`, `-3`, ..., cut so the id stays within 32
    /// characters.
    #[test]
    fn a_taken_id_gets_a_numbered_suffix_that_fits() {
        assert_eq!(
            derived_id("Home Office", &taken(&["home-office"])),
            "home-office-2",
            "second"
        );
        assert_eq!(
            derived_id("Home Office", &taken(&["home-office", "home-office-2"])),
            "home-office-3",
            "third"
        );
        let full = "a".repeat(32);
        assert_eq!(
            derived_id(&full, &taken(&[full.as_str()])),
            format!("{}-2", "a".repeat(30)),
            "cut to fit the suffix"
        );
        let hyphened = format!("{}-b", "a".repeat(29));
        assert_eq!(
            derived_id(&hyphened, &taken(&[hyphened.as_str()])),
            format!("{}-2", "a".repeat(29)),
            "no hyphen before the suffix"
        );
    }

    /// Todo 11: every derived id is a valid typed id.
    #[test]
    fn every_derived_id_is_a_slug() {
        let ids = taken(&["home-office", "router-1"]);
        for name in ["Home Office", CYRILLIC, "", &"x".repeat(80), "a-b", "9"] {
            let id = derived_id(name, &ids);
            assert!(is_slug(&id), "{name:?} -> {id}");
            assert!(!ids.contains(&id), "{name:?} -> {id} is free");
        }
    }
}
