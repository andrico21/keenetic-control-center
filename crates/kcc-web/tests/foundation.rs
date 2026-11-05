//! Web UI foundation: routes under `/ui`, hash-addressed assets with an immutable cache
//! policy, the generic localized 404 page, and the template lint (no inline style or
//! script, no `hx-on`, no visible text outside `t(...)`).

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::error::Error;
    use std::{fs, path::PathBuf};

    use axum::{
        Router,
        body::{Body, to_bytes},
        http::{HeaderName, Method, Request, StatusCode, header},
        response::Response,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use kcc_i18n::locale::Locale;
    use kcc_web::{BODY_LIMIT, WebState, nav::Section, web_router};
    use sha2::{Digest as _, Sha256};
    use tower::ServiceExt as _;

    /// Fallible test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// Largest response body a test reads.
    const BODY_CAP: usize = 0x0040_0000;

    /// The vendored htmx build, byte for byte as served.
    const HTMX: &[u8] = include_bytes!("../assets/vendor/htmx.min.js");

    /// The template directory.
    const TEMPLATES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");

    /// A copy of a page template with an inline style planted in it.
    const PLANTED_STYLE: &str = include_str!("fixtures/planted_style.html");

    /// Attributes whose values a visitor reads or hears.
    const VISIBLE_ATTRIBUTES: [&str; 8] = [
        "aria-label",
        "aria-description",
        "aria-roledescription",
        "aria-valuetext",
        "title",
        "alt",
        "placeholder",
        "label",
    ];

    /// Askama comment, block and expression delimiters.
    const TEMPLATE_DELIMITERS: [(&str, &str); 3] = [("{#", "#}"), ("{%", "%}"), ("{{", "}}")];

    /// The router under test, with English as the configured default locale.
    fn router() -> Router {
        web_router(WebState::new(Locale::En))
    }

    /// Sends one request through the router.
    async fn send(
        method: Method,
        path: &str,
        headers: &[(HeaderName, &str)],
        body: Body,
    ) -> Result<Response, Box<dyn Error>> {
        let mut request = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            request = request.header(name, *value);
        }
        Ok(router().oneshot(request.body(body)?).await?)
    }

    /// Sends `GET path` with `headers`.
    async fn get(path: &str, headers: &[(HeaderName, &str)]) -> Result<Response, Box<dyn Error>> {
        send(Method::GET, path, headers, Body::empty()).await
    }

    /// The response body as text.
    async fn text(response: Response) -> Result<String, Box<dyn Error>> {
        let bytes = to_bytes(response.into_body(), BODY_CAP).await?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    /// One response header as text.
    fn header_text(response: &Response, name: &HeaderName) -> Option<String> {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    }

    /// The opening tags named `name` (`<script`, `<link`, ...) in `html`, up to their `>`.
    fn tags<'html>(html: &'html str, name: &str) -> Vec<&'html str> {
        html.split(name)
            .skip(1)
            .filter_map(|tail| tail.split_once('>').map(|(tag, _)| tag))
            .collect()
    }

    /// The value of the double-quoted attribute `name` in an opening tag.
    fn attribute<'tag>(tag: &'tag str, name: &str) -> Option<&'tag str> {
        let (_, tail) = tag.split_once(&format!(" {name}=\""))?;
        tail.split_once('"').map(|(value, _)| value)
    }

    #[tokio::test]
    async fn root_and_bare_ui_redirect_to_the_dashboard() -> TestResult {
        for path in ["/", "/ui"] {
            let response = get(path, &[]).await?;
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{path}");
            assert_eq!(
                header_text(&response, &header::LOCATION).as_deref(),
                Some("/ui/"),
                "{path}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn hash_addressed_assets_are_immutable_with_their_content_type() -> TestResult {
        let page = text(get("/ui/", &[]).await?).await?;
        let script = tags(&page, "<script")
            .into_iter()
            .find(|tag| tag.contains("htmx.min.js"))
            .ok_or("no htmx script tag")?;
        let src = attribute(script, "src").ok_or("script has no src")?;
        assert!(src.starts_with("/ui/static/"), "{src}");
        let expected_integrity = format!("sha256-{}", STANDARD.encode(Sha256::digest(HTMX)));
        assert_eq!(
            attribute(script, "integrity"),
            Some(expected_integrity.as_str()),
            "integrity matches the vendored file"
        );

        let response = get(src, &[]).await?;
        assert_eq!(response.status(), StatusCode::OK, "{src}");
        assert_eq!(
            header_text(&response, &header::CONTENT_TYPE).as_deref(),
            Some("text/javascript; charset=utf-8"),
            "script content type"
        );
        assert_eq!(
            header_text(&response, &header::CACHE_CONTROL).as_deref(),
            Some("public, max-age=31536000, immutable"),
            "immutable cache"
        );
        let body = to_bytes(response.into_body(), BODY_CAP).await?;
        assert_eq!(body.as_ref(), HTMX, "served bytes are the vendored bytes");

        let link = tags(&page, "<link")
            .into_iter()
            .find(|tag| tag.contains("rel=\"stylesheet\""))
            .ok_or("no stylesheet link")?;
        let href = attribute(link, "href").ok_or("stylesheet has no href")?;
        assert!(
            attribute(link, "integrity").is_some_and(|value| value.starts_with("sha256-")),
            "stylesheet integrity"
        );
        let css = get(href, &[]).await?;
        assert_eq!(css.status(), StatusCode::OK, "{href}");
        assert_eq!(
            header_text(&css, &header::CONTENT_TYPE).as_deref(),
            Some("text/css; charset=utf-8"),
            "stylesheet content type"
        );

        let stale = get("/ui/static/0000000000000000/htmx.min.js", &[]).await?;
        assert_eq!(
            stale.status(),
            StatusCode::NOT_FOUND,
            "a wrong digest is not served"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_paths_get_a_generic_localized_404() -> TestResult {
        let probe = "/ui/no-such-page/../../etc/passwd%00<script>";
        let response = get(
            "/ui/no-such-page/deeper",
            &[(header::ACCEPT_LANGUAGE, "de-DE,de;q=0.9")],
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "status");
        assert_eq!(
            header_text(&response, &header::CONTENT_TYPE).as_deref(),
            Some("text/html; charset=utf-8"),
            "an HTML page, not the kit's JSON 404"
        );
        assert_eq!(
            header_text(&response, &header::CACHE_CONTROL).as_deref(),
            Some("no-store, max-age=0"),
            "never cached"
        );
        let html = text(response).await?;
        assert!(html.contains("<html lang=\"de\""), "negotiated locale");
        assert!(html.contains("Seite nicht gefunden"), "German title");
        for leak in [
            "no-such-page",
            "deeper",
            "panicked",
            ".rs",
            "src/",
            "kcc_web",
            "axum",
            "Error",
        ] {
            assert!(!html.contains(leak), "the 404 page leaks {leak}");
        }

        let encoded = get(&probe.replace('<', "%3C").replace('>', "%3E"), &[]).await?;
        assert_eq!(encoded.status(), StatusCode::NOT_FOUND, "encoded probe");
        let probed = text(encoded).await?;
        assert!(!probed.contains("passwd"), "no reflection of the path");

        let posted = send(Method::POST, "/ui/clients", &[], Body::empty()).await?;
        assert_eq!(posted.status(), StatusCode::NOT_FOUND, "non-GET under /ui");
        Ok(())
    }

    #[tokio::test]
    async fn oversized_bodies_are_refused() -> TestResult {
        let length = BODY_LIMIT.saturating_add(1);
        let response = send(
            Method::POST,
            "/ui/anything",
            &[(header::CONTENT_LENGTH, &length.to_string())],
            Body::from(vec![0_u8; length]),
        )
        .await?;
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "1 MiB cap"
        );
        Ok(())
    }

    #[tokio::test]
    async fn every_section_renders_inside_the_shell() -> TestResult {
        for section in Section::ALL {
            let response = get(section.href(), &[]).await?;
            assert_eq!(response.status(), StatusCode::OK, "{}", section.href());
            assert_eq!(
                header_text(&response, &header::CACHE_CONTROL).as_deref(),
                Some("no-store, max-age=0"),
                "{}",
                section.href()
            );
            let html = text(response).await?;
            let current = format!("href=\"{}\" aria-current=\"page\"", section.href());
            assert!(
                html.contains(&current),
                "{} is the current link",
                section.href()
            );
            assert_eq!(
                html.matches("aria-current=\"page\"").count(),
                1,
                "{}",
                section.href()
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn pages_load_only_pinned_scripts_and_styles() -> TestResult {
        let html = text(get("/ui/", &[]).await?).await?;
        assert!(
            html.contains(
                "<meta name=\"htmx-config\" content='{\"allowEval\":false,\"allowScriptTags\":false,\"includeIndicatorStyles\":false,\"selfRequestsOnly\":true}'>"
            ),
            "htmx configuration"
        );
        let scripts = tags(&html, "<script");
        assert_eq!(scripts.len(), 3, "htmx, the sse extension and app.js");
        for tag in scripts {
            let src = attribute(tag, "src").ok_or("inline script")?;
            assert!(src.starts_with("/ui/static/"), "{src}");
            assert!(attribute(tag, "integrity").is_some(), "{src} integrity");
        }
        assert!(!html.contains(" style="), "no inline style attribute");
        assert!(!html.contains("<style"), "no style element");
        assert!(!html.contains("hx-on"), "no hx-on handlers");
        assert!(
            !html.contains("http://") && !html.contains("https://"),
            "no CDN"
        );
        Ok(())
    }

    #[tokio::test]
    async fn theme_and_language_cookies_shape_the_page() -> TestResult {
        let html = text(
            get(
                "/ui/",
                &[
                    (header::COOKIE, "kcc_theme=dark; kcc_lang=kk"),
                    (header::ACCEPT_LANGUAGE, "de"),
                ],
            )
            .await?,
        )
        .await?;
        assert!(
            html.contains("<html lang=\"kk\" dir=\"ltr\" class=\"theme-dark\">"),
            "cookie locale and theme"
        );
        assert!(
            html.contains("<meta name=\"color-scheme\" content=\"dark\">"),
            "browser controls follow the theme"
        );
        assert!(
            html.contains("data-kcc-theme=\"dark\" aria-current=\"true\""),
            "theme menu marks dark"
        );
        assert!(
            html.contains("data-kcc-locale=\"kk\" aria-current=\"true\""),
            "language menu marks kk"
        );
        Ok(())
    }

    /// Every `.html` template under `templates/`, as `(path, text)`.
    fn templates() -> Result<Vec<(String, String)>, Box<dyn Error>> {
        let mut found = Vec::new();
        let mut pending = vec![PathBuf::from(TEMPLATES)];
        while let Some(dir) = pending.pop() {
            for entry in fs::read_dir(&dir)? {
                let path = entry?.path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path
                    .extension()
                    .is_some_and(|extension| extension == "html")
                {
                    let text = fs::read_to_string(&path)?;
                    found.push((path.display().to_string(), text));
                }
            }
        }
        Ok(found)
    }

    /// Every rule violation in one template.
    fn lint(template: &str) -> Vec<String> {
        let mut problems = Vec::new();
        let lower = template.to_ascii_lowercase();
        if has_attribute(&lower, "style") {
            problems.push("inline style= attribute".to_owned());
        }
        if lower.contains("<style") {
            problems.push("<style> element".to_owned());
        }
        if lower.contains("hx-on") {
            problems.push("hx-on attribute".to_owned());
        }
        for head in lower
            .split("<script")
            .skip(1)
            .map(|tail| tail.split('>').next().unwrap_or_default())
        {
            if !has_attribute(head, "src") {
                problems.push("<script> without src".to_owned());
            }
        }
        let markup = strip(&strip(template, &TEMPLATE_DELIMITERS), &[("<!--", "-->")]);
        let mut rest = markup.as_str();
        while let Some((text, after)) = rest.split_once('<') {
            check_text(text, &mut problems);
            let (tag, next) = after.split_once('>').unwrap_or((after, ""));
            for value in visible_attribute_values(tag) {
                check_text(value, &mut problems);
            }
            rest = next;
        }
        check_text(rest, &mut problems);
        problems
    }

    /// Whether `markup` has an attribute `name=` (after whitespace, before `=`).
    fn has_attribute(markup: &str, name: &str) -> bool {
        markup.match_indices(name).any(|(index, _)| {
            let after_space = markup
                .get(..index)
                .and_then(|head| head.chars().next_back())
                .is_some_and(char::is_whitespace);
            let assigned = markup
                .get(index.saturating_add(name.len())..)
                .is_some_and(|tail| tail.trim_start().starts_with('='));
            after_space && assigned
        })
    }

    /// `text` with every `open ... close` span replaced by one space.
    fn strip(text: &str, delimiters: &[(&str, &str)]) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some((at, open, close)) = delimiters
            .iter()
            .filter_map(|&(open, close)| rest.find(open).map(|at| (at, open, close)))
            .min_by_key(|&(at, _, _)| at)
        {
            out.push_str(rest.get(..at).unwrap_or_default());
            out.push(' ');
            rest = rest
                .get(at.saturating_add(open.len())..)
                .and_then(|inner| inner.split_once(close))
                .map_or("", |(_, tail)| tail);
        }
        out.push_str(rest);
        out
    }

    /// The quoted values of the visible attributes of one tag.
    fn visible_attribute_values(tag: &str) -> Vec<&str> {
        let mut values = Vec::new();
        for name in VISIBLE_ATTRIBUTES {
            for (index, _) in tag.match_indices(name) {
                let after_space = tag
                    .get(..index)
                    .and_then(|head| head.chars().next_back())
                    .is_some_and(char::is_whitespace);
                let Some(quoted) = tag
                    .get(index.saturating_add(name.len())..)
                    .and_then(|tail| tail.strip_prefix('='))
                else {
                    continue;
                };
                let Some(quote) = quoted
                    .chars()
                    .next()
                    .filter(|first| *first == '"' || *first == '\'')
                else {
                    continue;
                };
                if after_space {
                    let value = quoted
                        .get(1..)
                        .and_then(|inner| inner.split(quote).next())
                        .unwrap_or_default();
                    values.push(value);
                }
            }
        }
        values
    }

    /// Reports `text` when it holds anything but whitespace, digits, punctuation and
    /// character references.
    fn check_text(text: &str, problems: &mut Vec<String>) {
        let literal = without_references(text);
        if literal.chars().any(|character| {
            !(character.is_whitespace()
                || character.is_ascii_digit()
                || character.is_ascii_punctuation())
        }) {
            problems.push(format!("literal text outside t(): `{}`", text.trim()));
        }
    }

    /// `text` without character references such as `&nbsp;` or `&#160;`.
    fn without_references(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some((before, after)) = rest.split_once('&') {
            out.push_str(before);
            match after.split_once(';') {
                Some((name, tail))
                    if (1..=10).contains(&name.len())
                        && name.chars().all(|character| {
                            character.is_ascii_alphanumeric() || character == '#'
                        }) =>
                {
                    rest = tail;
                }
                Some(_) | None => {
                    out.push('&');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn every_template_passes_the_lint() -> TestResult {
        let found = templates()?;
        assert!(found.len() >= 4, "templates found: {}", found.len());
        for (path, template) in &found {
            let problems = lint(template);
            assert!(problems.is_empty(), "{path}: {}", problems.join("; "));
        }
        Ok(())
    }

    #[test]
    fn a_planted_inline_style_fails_the_lint() {
        let problems = lint(PLANTED_STYLE);
        assert_eq!(problems, ["inline style= attribute"], "planted fixture");
    }

    #[test]
    fn the_lint_catches_each_rule() {
        let cases = [
            ("<script>alert(1)</script>", "<script> without src"),
            (
                "<button hx-on:click=\"go()\">{{ t(keys::COMMON_OK) }}</button>",
                "hx-on attribute",
            ),
            ("<style>p{}</style>", "<style> element"),
            ("<p>Hello</p>", "literal text outside t(): `Hello`"),
            (
                "<img alt=\"Logo\" src=\"x\">",
                "literal text outside t(): `Logo`",
            ),
            (
                "<p>{# Hidden #}{% if x %}Shown{% endif %}</p>",
                "literal text outside t(): `Shown`",
            ),
        ];
        for (template, expected) in cases {
            let problems = lint(template);
            assert!(
                problems.iter().any(|problem| problem == expected),
                "{template}: {}",
                problems.join("; ")
            );
        }
        let clean = "<p class=\"x\" aria-label=\"{{ t(keys::WEB_NAV_LABEL) }}\">{{ t(keys::COMMON_OK) }}: 42 &middot; (1/2)</p><link rel=\"stylesheet\">";
        assert!(lint(clean).is_empty(), "{}", lint(clean).join("; "));
    }
}
