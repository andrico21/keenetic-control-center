//! Line scanner for `cancel-safety`: fully `pub` async fns and the test items to skip.

use crate::allow_gate::blank_non_code;

/// What [`scan`] found in one source file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FileScan {
    /// 1-based line and name of each unannotated fully `pub` async fn outside test items.
    missing: Vec<(usize, String)>,
    /// Number of fully `pub` async fns outside test items.
    checked: usize,
    /// Names of `#[cfg(test)] mod name;` declarations (out-of-line test modules).
    test_modules: Vec<String>,
}

impl FileScan {
    /// 1-based line and name of each unannotated fully `pub` async fn.
    pub(crate) fn missing(&self) -> &[(usize, String)] {
        &self.missing
    }

    /// Number of fully `pub` async fns outside test items.
    pub(crate) const fn checked(&self) -> usize {
        self.checked
    }

    /// Names of the out-of-line test modules this file declares.
    pub(crate) fn test_modules(&self) -> &[String] {
        &self.test_modules
    }
}

/// A `#[cfg(test)]` item: braced (skipped by line range) or an out-of-line `mod name;`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TestItem {
    /// 0-based first and last line of a braced item.
    Inline(usize, usize),
    /// The module name of `mod name;`.
    OutOfLine(String),
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
            TestItem::OutOfLine(name) => result.test_modules.push(name),
        }
    }
    for (index, line) in blank.iter().enumerate() {
        let in_test = ranges
            .iter()
            .any(|&(first, last)| (first..=last).contains(&index));
        let Some(name) = pub_async_fn_name(line) else {
            continue;
        };
        if in_test {
            continue;
        }
        result.checked = result.checked.saturating_add(1);
        if !has_marker(&raw, &blank, index) {
            result.missing.push((index.saturating_add(1), name));
        }
    }
    result
}

/// The fn name when the blanked `line` declares a fully `pub` async fn.
fn pub_async_fn_name(line: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    if words.next() != Some("pub") {
        return None;
    }
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
    (is_async && !name.is_empty()).then_some(name)
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
    let mut depth = 0_usize;
    for (offset, current) in rest.char_indices() {
        match (current, depth) {
            (';', 0) => {
                let header = rest.get(..offset)?;
                let mut words = header.split_whitespace();
                let is_module = words.any(|word| word == "mod");
                return words
                    .next()
                    .filter(|_| is_module)
                    .map(|name| TestItem::OutOfLine(name.to_owned()));
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
    use super::scan;

    /// Missing lines and names reported for `source`.
    fn missing(source: &str) -> Vec<(usize, String)> {
        scan(source).missing
    }

    /// Plain, method, attributed and doc-block forms are recognised.
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
                (1, "bare".to_owned()),
                (15, "method".to_owned()),
                (22, "after_other".to_owned()),
            ]
        );
        assert_eq!(scan(source).checked, 5, "{source}");
    }

    /// Inline `#[cfg(test)]` items are skipped and out-of-line ones are named.
    #[test]
    fn cfg_test_items_are_skipped() {
        let source = concat!(
            "#[cfg(test)]\nmod tests {\n    pub async fn helper() { let s = \"}\"; }\n}\n",
            "#[cfg(test)]\nmod more_tests;\n",
            "pub async fn live() {}\n",
        );
        let found = scan(source);
        assert_eq!(missing(source), [(7, "live".to_owned())]);
        assert_eq!(found.test_modules, ["more_tests"]);
    }
}
