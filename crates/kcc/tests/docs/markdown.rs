//! Markdown reading shared by the documentation checks.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// The repository root.
pub(crate) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `README.md` and every Markdown file directly under `docs/`, sorted.
pub(crate) fn documents() -> io::Result<Vec<PathBuf>> {
    let mut files = vec![root().join("README.md")];
    let mut docs = Vec::new();
    for entry in fs::read_dir(root().join("docs"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "md") {
            docs.push(path);
        }
    }
    docs.sort();
    files.extend(docs);
    Ok(files)
}

/// [`documents`] plus the other top-level Markdown files.
pub(crate) fn linked_documents() -> io::Result<Vec<PathBuf>> {
    let mut files = documents()?;
    for name in ["CHANGELOG.md", "CONTRIBUTING.md", "THIRD_PARTY_NOTICES.md"] {
        files.push(root().join(name));
    }
    Ok(files)
}

/// One fenced code block.
#[derive(Debug)]
pub(crate) struct Fence {
    /// The info string after the opening backticks.
    #[cfg_attr(
        not(unix),
        expect(dead_code, reason = "only the unix-only example runner reads it")
    )]
    pub info: String,
    /// The block's lines with the fence's indentation removed.
    pub body: String,
}

/// Every fenced code block of `text`, in document order.
#[cfg_attr(
    not(unix),
    expect(dead_code, reason = "the example runner is unix-only")
)]
pub(crate) fn fences(text: &str) -> Vec<Fence> {
    let mut found = Vec::new();
    let mut open: Option<(usize, Fence)> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        let indent = line.len().saturating_sub(trimmed.len());
        match open.take() {
            None => {
                if let Some(info) = trimmed.strip_prefix("```") {
                    let fence = Fence {
                        info: info.trim().to_owned(),
                        body: String::new(),
                    };
                    open = Some((indent, fence));
                }
            }
            Some((_, fence)) if trimmed == "```" => found.push(fence),
            Some((depth, mut fence)) => {
                let cut = line
                    .char_indices()
                    .take_while(|&(position, character)| position < depth && character == ' ')
                    .count();
                fence.body.push_str(line.get(cut..).unwrap_or_default());
                fence.body.push('\n');
                open = Some((depth, fence));
            }
        }
    }
    found
}

/// `text` without its fenced code blocks.
pub(crate) fn prose(text: &str) -> String {
    let mut kept = String::new();
    let mut inside = false;
    for line in text.lines() {
        let fence = line.trim_start().starts_with("```");
        if fence {
            inside = !inside;
        }
        if !fence && !inside {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    kept
}

/// The text inside the first pair of backticks of `line`.
pub(crate) fn first_code_span(line: &str) -> Option<&str> {
    let (_, rest) = line.split_once('`')?;
    let (span, _) = rest.split_once('`')?;
    Some(span)
}
