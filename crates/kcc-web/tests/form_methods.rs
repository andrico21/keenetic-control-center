//! Native browser submissions must never put POST form fields in a URL.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test code fails by panicking or returning an error"
)]
mod tests {
    use core::error::Error;
    use std::{fs, path::PathBuf};

    /// Reads quoted HTML attributes, skipping Askama expressions inside their values.
    fn attribute<'text>(tag: &'text str, name: &str) -> Option<&'text str> {
        let (_, rest) = tag.split_once(&format!(" {name}="))?;
        let quote = rest.chars().next()?;
        if !matches!(quote, '\'' | '"') {
            return None;
        }
        let value = rest.get(1..)?;
        let mut expression = false;
        for (index, character) in value.char_indices() {
            let suffix = value.get(index..)?;
            if suffix.starts_with("{{") {
                expression = true;
                continue;
            }
            if suffix.starts_with("}}") {
                expression = false;
                continue;
            }
            if character == quote && !expression {
                return value.get(..index);
            }
        }
        None
    }

    /// Every htmx POST form has the same native POST destination; no exceptions.
    #[test]
    fn every_htmx_post_form_has_matching_native_post() -> Result<(), Box<dyn Error>> {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mut pending = vec![manifest.join("templates"), manifest.join("src")];
        let mut violations = Vec::new();
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                for entry in fs::read_dir(path)? {
                    pending.push(entry?.path());
                }
                continue;
            }
            if path
                .extension()
                .is_none_or(|extension| !matches!(extension.to_str(), Some("html" | "rs")))
            {
                continue;
            }
            let source = fs::read_to_string(&path)?.replace("\\\"", "\"");
            for opening in source.split("<form").skip(1) {
                let tag = opening.split_once('>').ok_or("unclosed form tag")?.0;
                if let Some(destination) = attribute(tag, "hx-post")
                    && (attribute(tag, "method") != Some("post")
                        || attribute(tag, "action") != Some(destination))
                {
                    violations.push(format!("{}: {destination}", path.display()));
                }
            }
        }
        assert!(
            violations.is_empty(),
            "native POST violations: {violations:?}"
        );
        Ok(())
    }
}
