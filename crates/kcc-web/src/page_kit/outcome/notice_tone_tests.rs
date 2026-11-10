//! Every tone a notice can carry has its own rule in the stylesheet.
//!
//! `.notice` alone shows the success wash, so a tone without a
//! `.notice[data-tone="..."]` rule silently renders as success. The tones come from
//! [`super::Tone`] and from the literal `data-tone` values of every element of class
//! `notice` in the templates and the Rust sources (inline templates included).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking or returning an error"
)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};
    use core::error::Error;
    use std::{fs, path::Path};

    use super::super::Tone;

    /// The tone `.notice` shows without a `data-tone` rule.
    const DEFAULT_TONE: &str = "success";

    /// The declaration of the default tone's wash in a base `.notice` rule.
    const DEFAULT_WASH: &str = "background: var(--color-success-toast);";

    /// The opening of a tone rule's selector.
    const TONE_SELECTOR: &str = ".notice[data-tone=\"";

    /// The `data-tone` value of every [`Tone`]: a new variant fails to compile in the match
    /// until it is listed here.
    fn every_tone() -> [&'static str; 4] {
        [Tone::Success, Tone::Info, Tone::Warning, Tone::Error].map(|tone| match tone {
            Tone::Success | Tone::Info | Tone::Warning | Tone::Error => tone.value(),
        })
    }

    /// The tones `css` gives a `.notice[data-tone="..."]` rule.
    fn styled_tones(css: &str) -> BTreeSet<&str> {
        css.match_indices(TONE_SELECTOR)
            .filter_map(|(start, opening)| {
                let rest = css.get(start.saturating_add(opening.len())..)?;
                rest.split_once("\"]").map(|(tone, _)| tone)
            })
            .collect()
    }

    /// Whether a base `.notice` rule of `css` sets the default tone's wash.
    fn shows_default_wash(css: &str) -> bool {
        css.match_indices("\n.notice {").any(|(start, opening)| {
            css.get(start.saturating_add(opening.len())..)
                .and_then(|rest| rest.split_once('}'))
                .is_some_and(|(block, _)| block.contains(DEFAULT_WASH))
        })
    }

    /// The tag that opens at the start of `rest`, up to its `>` outside quotes.
    fn tag_text(rest: &str) -> Option<&str> {
        let mut quoted = false;
        for (index, character) in rest.char_indices() {
            match character {
                '"' => quoted = !quoted,
                '>' if !quoted => return rest.get(..index),
                _ => {}
            }
        }
        None
    }

    /// The value of the attribute `name` in `tag`.
    fn attribute<'tag>(tag: &'tag str, name: &str) -> Option<&'tag str> {
        let opening = format!(" {name}=\"");
        let start = tag.find(&opening)?.saturating_add(opening.len());
        tag.get(start..)?.split_once('"').map(|(value, _)| value)
    }

    /// The words of an attribute value outside its askama blocks:
    /// `{% if ok %}success{% else %}error{% endif %}` gives `success` and `error`, and
    /// `{{ outcome.tone() }}` gives nothing.
    fn literal_words(value: &str) -> Vec<String> {
        let mut plain = String::new();
        let mut rest = value;
        while let Some(start) = rest.find("{{").into_iter().chain(rest.find("{%")).min() {
            plain.push_str(rest.get(..start).unwrap_or_default());
            plain.push(' ');
            let tail = rest.get(start..).unwrap_or_default();
            let close = if tail.starts_with("{{") { "}}" } else { "%}" };
            rest = tail.split_once(close).map_or("", |(_, after)| after);
        }
        plain.push_str(rest);
        plain.split_whitespace().map(str::to_owned).collect()
    }

    /// The literal `data-tone` words of every element of class `notice` in `source`, a
    /// template or a Rust source (its escaped quotes read as quotes).
    fn notice_tones(source: &str) -> Vec<String> {
        let markup = source.replace("\\\"", "\"");
        let mut found = Vec::new();
        for (at, opening) in markup.match_indices(" class=\"") {
            let classes = markup
                .get(at.saturating_add(opening.len())..)
                .and_then(|rest| rest.split_once('"'))
                .map_or("", |(classes, _)| classes);
            if !classes.split_whitespace().any(|class| class == "notice") {
                continue;
            }
            let tag = markup
                .get(..at)
                .and_then(|head| head.rfind('<'))
                .and_then(|start| markup.get(start..))
                .and_then(tag_text);
            if let Some(value) = tag.and_then(|text| attribute(text, "data-tone")) {
                found.extend(literal_words(value));
            }
        }
        found
    }

    /// Every template and Rust source of the crate, as `(path below the crate, text)`.
    fn sources(root: &Path) -> Result<Vec<(String, String)>, Box<dyn Error>> {
        let mut found = Vec::new();
        let mut pending = vec![root.join("templates"), root.join("src")];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path
                    .extension()
                    .is_some_and(|extension| extension == "html" || extension == "rs")
                {
                    let text = fs::read_to_string(&path)?;
                    let below = path.strip_prefix(root).unwrap_or(&path);
                    found.push((below.display().to_string(), text));
                }
            }
        }
        Ok(found)
    }

    /// Every tone a notice can carry has its own `.notice[data-tone]` rule.
    ///
    /// A tone without one falls back to the success colours; the default tone is exempt
    /// only while a base rule shows it.
    #[test]
    fn every_notice_tone_has_its_own_rule() -> Result<(), Box<dyn Error>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let css = fs::read_to_string(root.join("assets/css/app.css"))?;
        assert!(
            shows_default_wash(&css),
            "a base .notice rule shows the {DEFAULT_TONE} wash"
        );
        let mut emitted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for tone in every_tone() {
            let _: bool = emitted
                .entry(tone.to_owned())
                .or_default()
                .insert("page_kit::outcome::Tone".to_owned());
        }
        for (path, text) in sources(root)? {
            for tone in notice_tones(&text) {
                let _: bool = emitted.entry(tone).or_default().insert(path.clone());
            }
        }
        assert!(
            emitted
                .values()
                .flatten()
                .any(|from| from.starts_with("templates")),
            "the scan reads literal notice tones from the templates: {emitted:?}"
        );
        let styled = styled_tones(&css);
        let missing: Vec<String> = emitted
            .iter()
            .filter(|&(tone, _)| tone != DEFAULT_TONE && !styled.contains(tone.as_str()))
            .map(|(tone, from)| {
                let places: Vec<&str> = from.iter().map(String::as_str).collect();
                format!("{tone} (from {})", places.join(", "))
            })
            .collect();
        assert!(
            missing.is_empty(),
            "notice tones without a .notice[data-tone] rule in assets/css/app.css: {}",
            missing.join("; ")
        );
        Ok(())
    }
}
