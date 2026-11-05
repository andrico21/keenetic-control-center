//! `catalog extract`: turn every cached manual into text and an outline file.

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use lopdf::{Document, Error as PdfError};
use serde::Serialize;

use crate::{
    Verdict,
    catalog::{self, Extraction, Lock},
    catalog_fetch,
    failure::GateError,
};

/// Container image used when `pdftotext` is not installed.
const PODMAN_IMAGE: &str = "docker.io/library/debian:12-slim";

/// Container script: install poppler, record its package version, convert every PDF.
const PODMAN_SCRIPT: &str = "set -e; apt-get update -qq; \
apt-get install -y -qq poppler-utils >/dev/null; \
dpkg-query -W -f='${Version}' poppler-utils > /w/.poppler-version; \
for f in /w/*/*.pdf; do pdftotext -layout -enc UTF-8 \"$f\" \"${f%.pdf}.txt\"; done";

/// One bookmark of a manual.
#[derive(Debug, Serialize)]
struct Bookmark {
    /// Nesting depth, 1 for a top-level bookmark.
    level: usize,
    /// The bookmark title.
    title: String,
    /// The page the bookmark points at.
    page: usize,
}

/// Extracts text and bookmarks for every `status = 200` lock entry whose PDF is cached.
///
/// # Errors
///
/// Returns a [`GateError`] when the lock cannot be read, `pdftotext` fails or a PDF
/// cannot be parsed.
pub(crate) fn run<W>(root: &Path, out: &mut W) -> Result<Verdict, GateError>
where
    W: io::Write,
{
    let lock_path = catalog::lock_path(root);
    let mut lock = Lock::load(&lock_path)?;
    let cache = catalog::cache_dir(root);
    let pdfs: Vec<PathBuf> = lock
        .entries
        .iter()
        .filter(|entry| !entry.absent)
        .map(|entry| {
            cache
                .join(&entry.version)
                .join(format!("{}.pdf", entry.model.to_lowercase()))
        })
        .filter(|path| path.is_file())
        .collect();
    let (method, poppler) = if native_poppler().is_some() {
        let version = native_text(&pdfs)?;
        ("native", version)
    } else {
        ("podman", podman_text(&cache)?)
    };
    writeln!(
        out,
        "extract: {} PDFs via {method}, poppler {poppler}",
        pdfs.len()
    )?;
    for pdf in &pdfs {
        let count = write_outline(pdf)?;
        writeln!(out, "extract {}: {count} bookmarks", pdf.display())?;
    }
    lock.extraction = Some(Extraction {
        method: method.to_owned(),
        poppler,
        date: catalog_fetch::today(),
    });
    lock.save(&lock_path)?;
    Ok(Verdict::Pass)
}

/// The version line of a locally installed `pdftotext`, or `None` when it is missing.
fn native_poppler() -> Option<String> {
    let output = Command::new("pdftotext").arg("-v").output().ok()?;
    let text = String::from_utf8_lossy(&output.stderr);
    text.lines().next().map(str::to_owned)
}

/// Runs the local `pdftotext` over `pdfs` and returns its version line.
///
/// # Errors
///
/// Returns [`GateError::Command`] when `pdftotext` cannot run or fails.
fn native_text(pdfs: &[PathBuf]) -> Result<String, GateError> {
    for pdf in pdfs {
        let status = Command::new("pdftotext")
            .args(["-layout", "-enc", "UTF-8"])
            .arg(pdf)
            .arg(pdf.with_extension("txt"))
            .status()
            .map_err(|source| command_error("pdftotext", source.to_string()))?;
        if !status.success() {
            return Err(command_error(
                "pdftotext",
                format!("{} exited with {status}", pdf.display()),
            ));
        }
    }
    native_poppler().ok_or_else(|| command_error("pdftotext -v", "no version output".to_owned()))
}

/// Runs `pdftotext` in a Debian container over the whole cache; returns the poppler
/// package version.
///
/// # Errors
///
/// Returns [`GateError::Command`] when the container fails, [`GateError::Read`] when
/// the version file is missing.
fn podman_text(cache: &Path) -> Result<String, GateError> {
    let mount = format!("{}:/w", cache.display());
    let status = Command::new("podman")
        .args([
            "run",
            "--rm",
            "-v",
            &mount,
            PODMAN_IMAGE,
            "sh",
            "-c",
            PODMAN_SCRIPT,
        ])
        .status()
        .map_err(|source| command_error("podman run", source.to_string()))?;
    if !status.success() {
        return Err(command_error("podman run", format!("exited with {status}")));
    }
    let version_file = cache.join(".poppler-version");
    let version = fs::read_to_string(&version_file).map_err(|source| GateError::Read {
        path: version_file.clone(),
        source,
    })?;
    Ok(version.trim().to_owned())
}

/// Builds a [`GateError::Command`].
fn command_error(program: &str, detail: String) -> GateError {
    GateError::Command {
        program: program.to_owned(),
        detail,
    }
}

/// Writes `<model>.outline.json` next to `pdf` and returns the bookmark count.
///
/// # Errors
///
/// Returns [`GateError::Pdf`] when the PDF cannot be parsed, [`GateError::Write`] when
/// the JSON cannot be written.
fn write_outline(pdf: &Path) -> Result<usize, GateError> {
    let pdf_error = |detail: String| GateError::Pdf {
        path: pdf.to_path_buf(),
        detail,
    };
    let document = Document::load(pdf).map_err(|source| pdf_error(source.to_string()))?;
    let bookmarks: Vec<Bookmark> = match document.get_toc() {
        Ok(toc) => toc
            .toc
            .into_iter()
            .map(|item| Bookmark {
                level: item.level,
                title: item.title,
                page: item.page,
            })
            .collect(),
        Err(PdfError::NoOutline) => Vec::new(),
        Err(source) => return Err(pdf_error(source.to_string())),
    };
    let json =
        serde_json::to_string_pretty(&bookmarks).map_err(|source| pdf_error(source.to_string()))?;
    let path = pdf.with_extension("outline.json");
    fs::write(&path, json).map_err(|source| GateError::Write {
        path,
        detail: source.to_string(),
    })?;
    Ok(bookmarks.len())
}
