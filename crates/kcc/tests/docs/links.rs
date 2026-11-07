//! Every relative link and anchor in the documentation resolves.

use alloc::collections::BTreeSet;
use core::error::Error;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use tempfile::TempDir;

use super::markdown::{linked_documents, prose, root};

/// Link targets of `text` (inline links and images), outside fenced code.
fn targets(text: &str) -> Vec<String> {
    let body = prose(text);
    body.split("](")
        .skip(1)
        .filter_map(|rest| rest.split_once(')').map(|(target, _)| target))
        .map(|target| {
            target
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

/// GitHub's anchor for a heading.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|character| match character {
            ' ' => Some('-'),
            '-' | '_' => Some(character),
            other if other.is_alphanumeric() => Some(other),
            _ => None,
        })
        .collect()
}

/// Every anchor of the Markdown file `text`.
fn anchors(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for line in prose(text).lines() {
        if let Some(heading) = line.strip_prefix('#') {
            let base = slug(heading.trim_start_matches('#'));
            let mut candidate = base.clone();
            let mut counter = 0_u32;
            while found.contains(&candidate) {
                counter = counter.saturating_add(1);
                candidate = format!("{base}-{counter}");
            }
            let _: bool = found.insert(candidate);
        }
    }
    found
}

/// The broken relative links of the Markdown file at `path`.
pub(crate) fn broken(path: &Path) -> io::Result<Vec<String>> {
    let text = fs::read_to_string(path)?;
    let base = path.parent().map_or_else(PathBuf::new, Path::to_path_buf);
    let mut problems = Vec::new();
    for target in targets(&text) {
        if target.contains("://") || target.starts_with("mailto:") || target.is_empty() {
            continue;
        }
        let (file, anchor) = target.split_once('#').unwrap_or((target.as_str(), ""));
        let resolved = if file.is_empty() {
            path.to_path_buf()
        } else {
            base.join(file)
        };
        if !resolved.exists() {
            problems.push(format!("{}: missing {target}", path.display()));
            continue;
        }
        let markdown = resolved
            .extension()
            .is_some_and(|extension| extension == "md");
        if !anchor.is_empty()
            && markdown
            && !anchors(&fs::read_to_string(&resolved)?).contains(anchor)
        {
            problems.push(format!("{}: missing anchor {target}", path.display()));
        }
    }
    Ok(problems)
}

#[test]
fn every_relative_link_resolves() -> Result<(), Box<dyn Error>> {
    let mut problems = Vec::new();
    for document in linked_documents()? {
        problems.extend(broken(&document)?);
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    Ok(())
}

#[test]
fn a_broken_link_or_anchor_is_reported() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let page = directory.path().join("page.md");
    fs::write(
        &page,
        "# Title\n\n[ok](#title) [gone](missing.md) [bad](#nowhere)\n",
    )?;
    let problems = broken(&page)?;
    assert_eq!(problems.len(), 2, "{problems:?}");
    Ok(())
}

#[test]
fn lychee_offline_passes_when_installed() -> Result<(), Box<dyn Error>> {
    let mut command = Command::new("lychee");
    let _: &mut Command = command
        .args(["--offline", "--no-progress"])
        .args(linked_documents()?)
        .current_dir(root())
        .stdin(Stdio::null());
    let output = match command.output() {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            tracing::info!("lychee is not installed; only the Rust link check ran");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
