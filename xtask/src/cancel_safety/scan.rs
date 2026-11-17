//! Line scanner for `cancel-safety`: async fns of every visibility and the test items
//! to skip.

use crate::allow_gate::blank_non_code;

/// The declared visibility of an async fn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Visibility {
    /// `pub`.
    Public,
    /// `pub(crate)`.
    Crate,
    /// `pub(super)`.
    Super,
    /// `pub(self)` or `pub(in path)`.
    Restricted,
    /// No visibility keyword (private, trait items and trait-impl methods included).
    Private,
}

impl Visibility {
    /// Every visibility, in report order.
    pub(crate) const ALL: [Self; 5] = [
        Self::Public,
        Self::Crate,
        Self::Super,
        Self::Restricted,
        Self::Private,
    ];

    /// The label printed in the report.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Public => "pub",
            Self::Crate => "pub(crate)",
            Self::Super => "pub(super)",
            Self::Restricted => "pub(in)",
            Self::Private => "private",
        }
    }
}

/// One async fn declaration outside test items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AsyncFn {
    /// 1-based line of the declaration.
    line: usize,
    /// Declared visibility.
    visibility: Visibility,
    /// The fn name.
    name: String,
    /// Whether the block directly above carries a cancel-safety comment.
    annotated: bool,
}

impl AsyncFn {
    /// 1-based line of the declaration.
    pub(crate) const fn line(&self) -> usize {
        self.line
    }

    /// Declared visibility.
    pub(crate) const fn visibility(&self) -> Visibility {
        self.visibility
    }

    /// The fn name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Whether the block directly above carries a cancel-safety comment.
    pub(crate) const fn is_annotated(&self) -> bool {
        self.annotated
    }
}

/// What [`scan`] found in one source file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FileScan {
    /// Every async fn outside test items, in source order.
    found: Vec<AsyncFn>,
    /// `#[cfg(test)] mod name;` declarations (out-of-line test modules).
    test_modules: Vec<TestModule>,
}

/// An out-of-line `#[cfg(test)] mod name;` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TestModule {
    /// The module name.
    name: String,
    /// The `#[path = "..."]` value, relative to the declaring file's directory.
    path: Option<String>,
}

impl TestModule {
    /// The module name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The `#[path = "..."]` value, relative to the declaring file's directory.
    pub(crate) fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl FileScan {
    /// Every async fn outside test items, annotated or not.
    pub(crate) fn found(&self) -> &[AsyncFn] {
        &self.found
    }

    /// The out-of-line test modules this file declares.
    pub(crate) fn test_modules(&self) -> &[TestModule] {
        &self.test_modules
    }
}

/// A `#[cfg(test)]` item: braced (skipped by line range) or an out-of-line `mod name;`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TestItem {
    /// 0-based first and last line of a braced item.
    Inline(usize, usize),
    /// The module name of `mod name;` with the 0-based lines from `#[cfg(test)]` to
    /// the declaration.
    OutOfLine(String, usize, usize),
}

/// Scans one source file.
pub(crate) fn scan(source: &str) -> FileScan {
    let code = blank_non_code(source);
    let raw: Vec<&str> = source.lines().collect();
    let blank: Vec<&str> = code.lines().collect();
    let mut ranges = Vec::new();
    let mut result = FileScan::default();
    for item in test_items(&code) {
        match item {
            TestItem::Inline(first, last) => ranges.push((first, last)),
            TestItem::OutOfLine(name, first, last) => {
                let path = raw
                    .get(first..=last)
                    .unwrap_or_default()
                    .iter()
                    .find_map(|line| path_attribute(line));
                result.test_modules.push(TestModule { name, path });
            }
        }
    }
    for (index, line) in blank.iter().enumerate() {
        let in_test = ranges
            .iter()
            .any(|&(first, last)| (first..=last).contains(&index));
        let Some((visibility, name)) = async_fn(line) else {
            continue;
        };
        if in_test {
            continue;
        }
        result.found.push(AsyncFn {
            line: index.saturating_add(1),
            visibility,
            name,
            annotated: has_marker(&raw, &blank, index),
        });
    }
    result
}

/// The visibility and name when the blanked `line` declares an async fn.
fn async_fn(line: &str) -> Option<(Visibility, String)> {
    let (visibility, rest) = split_visibility(line.trim_start());
    let mut words = rest.split_whitespace();
    let mut is_async = false;
    for word in words.by_ref() {
        match word {
            "async" => is_async = true,
            "const" | "unsafe" | "extern" => {}
            "fn" => break,
            _ => return None,
        }
    }
    let name: String = words
        .next()?
        .chars()
        .take_while(|current| current.is_alphanumeric() || *current == '_')
        .collect();
    (is_async && !name.is_empty()).then_some((visibility, name))
}

/// The leading visibility of `line` and the text after it.
fn split_visibility(line: &str) -> (Visibility, &str) {
    let Some(after) = line.strip_prefix("pub") else {
        return (Visibility::Private, line);
    };
    if let Some(scoped) = after.trim_start().strip_prefix('(') {
        let Some((scope, rest)) = scoped.split_once(')') else {
            return (Visibility::Private, line);
        };
        let visibility = match scope.trim() {
            "crate" => Visibility::Crate,
            "super" => Visibility::Super,
            _ => Visibility::Restricted,
        };
        (visibility, rest)
    } else if after.starts_with(char::is_whitespace) {
        (Visibility::Public, after)
    } else {
        (Visibility::Private, line)
    }
}

/// Whether the comment and attribute block directly above line `index` carries a
/// `cancel-safe:` or `NOT cancel-safe:` comment (line or doc comment).
fn has_marker(raw: &[&str], blank: &[&str], index: usize) -> bool {
    for at in (0..index).rev() {
        let text = raw.get(at).map_or("", |line| line.trim());
        let code = blank.get(at).map_or("", |line| line.trim());
        if text.is_empty() {
            return false;
        }
        if code.is_empty() {
            let body = text.trim_start_matches(['/', '!', '*']).trim_start();
            if body.starts_with("cancel-safe:") || body.starts_with("NOT cancel-safe:") {
                return true;
            }
        } else if code.ends_with(['}', ';', '{']) {
            return false;
        } else {
            // An attribute line between the comment block and the fn.
        }
    }
    false
}

/// Every `#[cfg(test)]` item in the blanked `code`.
fn test_items(code: &str) -> Vec<TestItem> {
    let mut items = Vec::new();
    for (at, _) in code.match_indices("#[cfg(test)]") {
        let Some(rest) = code.get(at..) else {
            continue;
        };
        let first = line_of(code, at);
        if let Some(item) = item_after(rest, first) {
            items.push(item);
        }
    }
    items
}

/// The item that starts in `rest` (which begins at 0-based line `first`).
fn item_after(rest: &str, first: usize) -> Option<TestItem> {
    let (mut depth, mut nest) = (0_usize, 0_usize);
    for (offset, current) in rest.char_indices() {
        match current {
            '(' | '[' => nest = nest.saturating_add(1),
            ')' | ']' => nest = nest.saturating_sub(1),
            _ => {}
        }
        if nest > 0 {
            continue;
        }
        match (current, depth) {
            (';', 0) => {
                let header = rest.get(..offset)?;
                let mut words = header.split_whitespace();
                let is_module = words.any(|word| word == "mod");
                let last = first.saturating_add(line_of(rest, offset));
                return words
                    .next()
                    .filter(|_| is_module)
                    .map(|name| TestItem::OutOfLine(name.to_owned(), first, last));
            }
            ('{', _) => depth = depth.saturating_add(1),
            ('}' | ',', 0) => return None,
            ('}', 1) => {
                let last = first.saturating_add(line_of(rest, offset));
                return Some(TestItem::Inline(first, last));
            }
            ('}', _) => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    None
}

/// The value of a `#[path = "..."]` attribute on the raw `line`.
fn path_attribute(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix("#[path")?.trim_start();
    let quoted = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
    quoted.split_once('"').map(|(value, _)| value.to_owned())
}

/// 0-based line of byte offset `at` in `text`.
fn line_of(text: &str, at: usize) -> usize {
    text.get(..at)
        .map_or(0, |before| before.matches('\n').count())
}

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use super::{TestModule, Visibility, scan};

    /// Line, visibility and name of each unannotated async fn in `source`.
    fn missing(source: &str) -> Vec<(usize, Visibility, String)> {
        scan(source)
            .found
            .into_iter()
            .filter(|found| !found.annotated)
            .map(|found| (found.line, found.visibility, found.name))
            .collect()
    }

    /// Plain, method, attributed and doc-block forms are recognised at every visibility.
    #[test]
    fn marker_forms() {
        let source = concat!(
            "pub async fn bare() {}\n",
            "\n",
            "/// Doc.\n",
            "// cancel-safe: a read.\n",
            "pub async fn read() {}\n",
            "/// Doc.\n",
            "/// NOT cancel-safe: a write.\n",
            "#[expect(\n    clippy::x,\n    reason = \"r\"\n)]\n",
            "pub async fn write() {}\n",
            "impl A {\n",
            "    /// Doc.\n",
            "    pub async fn method(&self) {}\n",
            "    pub(crate) async fn crate_only(&self) {}\n",
            "    async fn private(&self) {}\n",
            "    pub fn sync(&self) {}\n",
            "}\n",
            "// cancel-safe: not adjacent.\n",
            "fn other() {}\n",
            "pub async fn after_other() {}\n",
        );
        assert_eq!(
            missing(source),
            [
                (1, Visibility::Public, "bare".to_owned()),
                (15, Visibility::Public, "method".to_owned()),
                (16, Visibility::Crate, "crate_only".to_owned()),
                (17, Visibility::Private, "private".to_owned()),
                (22, Visibility::Public, "after_other".to_owned()),
            ]
        );
        assert_eq!(scan(source).found.len(), 7, "{source}");
    }

    /// Restricted, private, trait and trait-impl async fns are checked; async blocks,
    /// async closures, sync fns and identifiers that start with `pub` are not fns.
    #[test]
    fn every_visibility_is_checked() {
        let source = concat!(
            "pub(super) async fn up() {}\n",
            "pub(in crate::a) async fn scoped() {}\n",
            "pub(self) async fn own() {}\n",
            "pub(crate) const async unsafe fn odd() {}\n",
            "trait T {\n",
            "    async fn declared(&self);\n",
            "}\n",
            "impl T for S {\n",
            "    // NOT cancel-safe: a write.\n",
            "    async fn declared(&self) {}\n",
            "}\n",
            "fn sync() {\n",
            "    let block = async move { 1 };\n",
            "    let closure = async |x: u8| x;\n",
            "    let text = \"async fn quoted() {}\";\n",
            "    // async fn commented() {}\n",
            "}\n",
            "pub_async fn not_a_keyword() {}\n",
        );
        assert_eq!(
            missing(source),
            [
                (1, Visibility::Super, "up".to_owned()),
                (2, Visibility::Restricted, "scoped".to_owned()),
                (3, Visibility::Restricted, "own".to_owned()),
                (4, Visibility::Crate, "odd".to_owned()),
                (6, Visibility::Private, "declared".to_owned()),
            ]
        );
        assert_eq!(scan(source).found.len(), 6, "{source}");
    }

    /// Inline `#[cfg(test)]` items (with their `#[tokio::test]` fns) are skipped and
    /// out-of-line ones are named, with their `#[path]` when given.
    #[test]
    fn cfg_test_items_are_skipped() {
        let source = concat!(
            "#[cfg(test)]\nmod tests {\n    pub async fn helper() { let s = \"}\"; }\n",
            "    #[tokio::test]\n    async fn probe() {}\n}\n",
            "#[cfg(test)]\nmod more_tests;\n",
            "#[cfg(test)]\nasync fn test_only() {}\n",
            "#[cfg(test)]\n#[path = \"live_tests.rs\"]\n",
            "#[expect(clippy::a, clippy::b, reason = \"r\")]\nmod tests;\n",
            "async fn live() {}\n",
        );
        let found = scan(source);
        assert_eq!(
            missing(source),
            [(15, Visibility::Private, "live".to_owned())]
        );
        assert_eq!(
            found.test_modules,
            [
                TestModule {
                    name: "more_tests".to_owned(),
                    path: None,
                },
                TestModule {
                    name: "tests".to_owned(),
                    path: Some("live_tests.rs".to_owned()),
                },
            ]
        );
    }
}
