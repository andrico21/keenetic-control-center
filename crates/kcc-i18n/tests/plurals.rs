//! CLDR plural categories: `{ $count } items` for 1, 2, 5 and 21 in every locale.
//!
//! Expected strings live in `fixtures/plurals.txt` so translated text never appears as a
//! Rust string literal.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, str};

    use fluent_bundle::FluentArgs;
    use kcc_i18n::{bundle::tr, keys, locale::Locale};

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// `locale|count|expected` rows; `#` lines are comments.
    const FIXTURE: &[u8] = include_bytes!("fixtures/plurals.txt");

    #[test]
    fn items_count_uses_cldr_categories_in_every_locale() -> TestResult {
        let mut covered = Vec::new();
        for line in str::from_utf8(FIXTURE)?.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let mut fields = line.splitn(3, '|');
            let (Some(tag), Some(count), Some(expected)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(format!("malformed fixture row: {line}").into());
            };
            let locale = Locale::from_tag(tag).ok_or_else(|| format!("unknown locale {tag}"))?;
            let mut args = FluentArgs::new();
            args.set("count", count.parse::<u32>()?);
            let actual = tr(locale, keys::COMMON_ITEMS_COUNT, Some(&args));
            assert_eq!(actual, expected, "{tag} count={count}");
            covered.push((locale, count.to_owned()));
        }
        for locale in Locale::ALL {
            for count in ["1", "2", "5", "21"] {
                assert!(
                    covered.contains(&(locale, count.to_owned())),
                    "fixture lacks {} count={count}",
                    locale.tag()
                );
            }
        }
        Ok(())
    }
}
