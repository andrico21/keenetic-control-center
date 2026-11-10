//! Notice surfaces: every `.notice` rule paints an opaque pair whose contrast is known.
//!
//! A notice sits on the canvas, on chrome or inside a dialog's raised surface. A
//! translucent wash composites into a different colour on each, so its text contrast
//! cannot be read from the stylesheet: the 16% dark washes left info and error notices at
//! 4.04:1 and 4.16:1 inside dialogs. A rule whose selector ends in a `.notice` compound
//! (`.notice`, `.notice[data-tone="error"]`, `.dialog .notice`, not `.notice__title`) and
//! sets `background` or `color` sets both, each as `var()` of a custom property that is a
//! `light-dark()` pair of literal six-digit hex colours, and the pair clears
//! [`MIN_TEXT_CONTRAST`] in both themes.

use super::{MIN_TEXT_CONTRAST, color_pair, contrast};

/// The stylesheet as problems name it.
const STYLESHEET: &str = "css/app.css";

/// One rule whose selector ends in a `.notice` compound.
struct NoticeRule<'css> {
    /// The selector list, trimmed.
    selector: &'css str,
    /// The value of its `background` or `background-color` declaration.
    background: Option<&'css str>,
    /// The value of its `color` declaration.
    color: Option<&'css str>,
}

/// Appends a problem for every notice rule whose surface and ink are not both opaque
/// literal pairs, or whose text contrast in either theme is below [`MIN_TEXT_CONTRAST`].
///
/// A rule that paints only one of the two is a problem too: its pair could not be checked.
pub(super) fn check(css: &str, problems: &mut Vec<String>) {
    let plain = uncommented(css);
    for rule in notice_rules(&plain) {
        let selector = rule.selector;
        let (background, color) = match (rule.background, rule.color) {
            (None, None) => continue,
            (Some(background), Some(color)) => (background, color),
            (Some(_), None) | (None, Some(_)) => {
                problems.push(format!(
                    "{STYLESHEET}: {selector} paints only one of background and color; a notice rule paints both"
                ));
                continue;
            }
        };
        let (Some(surface), Some(ink)) = (
            literal_pair(&plain, background),
            literal_pair(&plain, color),
        ) else {
            problems.push(format!(
                "{STYLESHEET}: {selector} paints background {background} and color {color}; each must be var() of a light-dark() pair of literal six-digit hex colours"
            ));
            continue;
        };
        for (theme, surface_color, ink_color) in
            [("light", surface.0, ink.0), ("dark", surface.1, ink.1)]
        {
            let ratio = contrast(surface_color, ink_color);
            if ratio < MIN_TEXT_CONTRAST {
                problems.push(format!(
                    "{STYLESHEET}: {selector} {theme} contrast is {ratio:.2}:1, below {MIN_TEXT_CONTRAST:.1}:1"
                ));
            }
        }
    }
}

/// The (light, dark) colours `value` names, when it is `var()` of a custom property that
/// is a `light-dark()` pair of literal six-digit hex colours.
fn literal_pair(css: &str, value: &str) -> Option<([u8; 3], [u8; 3])> {
    let name = value.strip_circumfix("var(", ")")?;
    color_pair(css, name.trim())
}

/// `css` without its `/* */` comments.
fn uncommented(css: &str) -> String {
    let mut plain = String::with_capacity(css.len());
    let mut rest = css;
    while let Some((before, after)) = rest.split_once("/*") {
        plain.push_str(before);
        rest = after.split_once("*/").map_or("", |(_, tail)| tail);
    }
    plain.push_str(rest);
    plain
}

/// Every rule of the uncommented `css` whose selector ends in a `.notice` compound, with
/// its surface and ink declarations.
fn notice_rules(css: &str) -> Vec<NoticeRule<'_>> {
    css.split('}')
        .filter_map(|chunk| {
            let (head, body) = chunk.rsplit_once('{')?;
            let selector = head
                .rsplit_once('{')
                .map_or(head, |(_, inner)| inner)
                .trim();
            ends_in_notice(selector).then(|| declarations(selector, body))
        })
        .collect()
}

/// Whether a selector of the list `selector` ends in a `.notice` compound: the class
/// alone, with attributes or pseudo-classes, or after an ancestor.
fn ends_in_notice(selector: &str) -> bool {
    selector.split(',').any(|part| {
        part.trim()
            .rsplit([' ', '\n', '\t', '>', '+', '~'])
            .next()
            .and_then(|compound| compound.strip_prefix(".notice"))
            .is_some_and(|rest| {
                !rest.starts_with(|character: char| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                })
            })
    })
}

/// The notice rule `selector` with the surface and ink of its declaration `body`.
fn declarations<'css>(selector: &'css str, body: &'css str) -> NoticeRule<'css> {
    let mut rule = NoticeRule {
        selector,
        background: None,
        color: None,
    };
    for declaration in body.split(';') {
        let Some((property, value)) = declaration.split_once(':') else {
            continue;
        };
        match property.trim() {
            "background" | "background-color" => rule.background = Some(value.trim()),
            "color" => rule.color = Some(value.trim()),
            _ => {}
        }
    }
    rule
}

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::{fs, path::Path};

    use tempfile::TempDir;

    use super::{check, notice_rules, uncommented};
    use crate::assets::check_text_contrast;

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// Literal toast pairs, a translucent danger wash and seven notice rules.
    ///
    /// The commented base rule and the warning rule are sound; error paints the
    /// translucent wash, `.dialog .notice` paints ink on its own surface and info paints
    /// only its ink; `.notice__title` and the role rule paint no notice surface.
    const FIXTURE: &str = ":root {\n\
        --color-success-toast: light-dark(#defbe6, #2b3e30);\n\
        --color-success-ink: light-dark(#0e6027, #6fdc8c);\n\
        --color-danger-toast: light-dark(#fff1f1, #482c2e);\n\
        --color-danger-ink: light-dark(#a2191f, #ff8389);\n\
        --color-danger-wash: light-dark(#fff1f1, rgb(250 77 86 / 0.16));\n\
        --color-warning-toast: light-dark(#fcf4d6, #463f24);\n\
        --color-warning-ink: light-dark(#684e00, #f1c21b);\n\
        --color-info-toast: light-dark(#edf5ff, #2b3649);\n\
        --color-info-ink: light-dark(#0043ce, #78a9ff);\n}\n\
        .notice {\n  padding: 1rem;\n  /* the default tone; dialogs: see below */\n\
        background: var(--color-success-toast);\n  color: var(--color-success-ink);\n}\n\
        .notice[data-tone=\"warning\"] { background: var(--color-warning-toast); color: var(--color-warning-ink); }\n\
        .notice[data-tone=\"error\"] { background: var(--color-danger-wash); color: var(--color-danger-ink); }\n\
        .dialog .notice { background-color: var(--color-info-toast); color: var(--color-info-toast); }\n\
        .notice[data-tone=\"info\"] { color: var(--color-info-ink); }\n\
        .notice__title { color: var(--color-danger-ink); }\n\
        .notice[role=\"note\"] { display: block; }\n";

    /// The gate's contrast step reports each unsound notice rule and nothing else.
    #[test]
    fn translucent_one_sided_or_dim_notice_rules_fail_the_contrast_step() -> TestResult {
        let dir = TempDir::new()?;
        fs::create_dir_all(dir.path().join("css"))?;
        fs::write(dir.path().join("css/app.css"), FIXTURE)?;
        let mut problems = Vec::new();
        check_text_contrast(dir.path(), &mut problems)?;
        for (selector, detail) in [
            (".notice[data-tone=\"error\"] ", "var(--color-danger-wash)"),
            (".dialog .notice ", "light contrast is 1.00:1"),
            (".dialog .notice ", "dark contrast is 1.00:1"),
            (
                ".notice[data-tone=\"info\"] ",
                "only one of background and color",
            ),
        ] {
            let opening = format!("css/app.css: {selector}");
            assert!(
                problems
                    .iter()
                    .any(|problem| problem.starts_with(&opening) && problem.contains(detail)),
                "{selector}{detail}: {problems:?}"
            );
        }
        assert_eq!(problems.len(), 4, "only the unsound rules: {problems:?}");
        Ok(())
    }

    /// The shipped notice rules pass, and the scan reaches the base rule and every tone's.
    #[test]
    fn the_shipped_notice_rules_paint_opaque_readable_pairs() -> TestResult {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../crates/kcc-web/assets/css/app.css");
        let css = fs::read_to_string(path)?;
        let mut problems = Vec::new();
        check(&css, &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
        let plain = uncommented(&css);
        let painted: Vec<&str> = notice_rules(&plain)
            .into_iter()
            .filter(|rule| rule.background.is_some())
            .map(|rule| rule.selector)
            .collect();
        for selector in [
            ".notice",
            ".notice[data-tone=\"info\"]",
            ".notice[data-tone=\"warning\"]",
            ".notice[data-tone=\"error\"]",
            ".notice[data-tone=\"neutral\"]",
        ] {
            assert!(painted.contains(&selector), "{selector} in {painted:?}");
        }
        Ok(())
    }
}
