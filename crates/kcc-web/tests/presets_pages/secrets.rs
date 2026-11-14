//! No secret value of a preset reaches a user without `RevealSecrets`: not in a page, a
//! fragment, the live stream, a download, nor in a file kcc keeps; Reveal shows it to a
//! role that has the permission.

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use std::{fs, path::Path};

    use axum::http::StatusCode;

    use crate::{
        flow::{DNS_LINES, apply, finish, redirected, seed, start},
        setup,
        support::{
            outcome::TestResult,
            page::{assert_native_post, text},
            web::{Browser, Fixture},
        },
    };

    /// The source user's password.
    const SOURCE_PASSWORD: &str = "alice-source-passphrase";

    /// The password typed for the user on the target.
    const TARGET_PASSWORD: &str = "alice-target-passphrase";

    /// Every file below `dir`, by path, as text.
    fn files(dir: &Path) -> TestResult<Vec<(String, String)>> {
        let mut found = Vec::new();
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                found.extend(files(&path)?);
            } else {
                let bytes = fs::read(&path)?;
                found.push((
                    path.display().to_string(),
                    String::from_utf8_lossy(&bytes).into_owned(),
                ));
            }
        }
        Ok(found)
    }

    /// The word following `marker` in `text`.
    fn word_after(text: &str, marker: &str) -> TestResult<String> {
        text.split(marker)
            .nth(1)
            .and_then(|tail| tail.split_whitespace().next())
            .map(str::to_owned)
            .ok_or_else(|| format!("no word after {marker}").into())
    }

    /// The body of `GET path` as `browser`.
    async fn page(fixture: &Fixture, browser: &Browser, path: &str) -> TestResult<String> {
        text(fixture.get(path, browser).await?).await
    }

    /// Captures the branch-office preset from `prod-1` as `browser`, keeping every body
    /// served in `served`; returns the preset's id.
    async fn captured(
        fixture: &Fixture,
        browser: &Browser,
        served: &mut Vec<String>,
    ) -> TestResult<String> {
        let groups = [
            ("group", "dns-secure"),
            ("group", "vpn-clients"),
            ("group", "router-users"),
        ];
        let read = fixture
            .post_multipart(
                "/ui/presets/new",
                browser,
                (&[("kind", "router"), ("router", "prod-1")], None),
            )
            .await?;
        let draft = redirected(&read)?;
        served.push(page(fixture, browser, &draft).await?);
        let preview = fixture
            .post_form(&format!("{draft}/preview"), browser, &groups)
            .await?;
        served.push(text(preview).await?);
        let mut named = groups.to_vec();
        named.push(("name", "Branch office"));
        let preset = redirected(&fixture.post_form(&draft, browser, &named).await?)?;
        served.push(page(fixture, browser, &preset).await?);
        served.push(page(fixture, browser, "/ui/presets").await?);
        Ok(preset.rsplit('/').next().ok_or("preset id")?.to_owned())
    }

    /// Applies preset `id` to `lab-1` as `browser` with the target password typed and
    /// keeps it unsaved, keeping every body served in `served`; returns the run's page.
    async fn applied(
        fixture: &Fixture,
        browser: &Browser,
        id: &str,
        served: &mut Vec<String>,
    ) -> TestResult<String> {
        let run = start(fixture, browser, id).await?;
        for (path, pairs) in [
            ("target", vec![("router", "lab-1")]),
            ("target/continue", Vec::new()),
            ("options", vec![("mode", "merge"), ("regenerate", "yes")]),
            ("review/continue", Vec::new()),
        ] {
            let response = fixture
                .post_form(&format!("{run}/{path}"), browser, &pairs)
                .await?;
            if response.status() != StatusCode::OK {
                return Err(format!("{path}: {}", response.status()).into());
            }
        }
        let inputs = page(fixture, browser, &run).await?;
        assert_native_post(&inputs)?;
        let typed = [("password-0", TARGET_PASSWORD)];
        let response = fixture
            .post_form(&format!("{run}/inputs"), browser, &typed)
            .await?;
        assert_eq!(response.status(), StatusCode::OK, "inputs accepted");
        served.push(page(fixture, browser, &run).await?);
        let stream = apply(fixture, browser, &run).await?;
        for sent in [
            "interface Wireguard0 wireguard private-key</code>",
            "user alice password plain &#60;redacted&#62;</code>",
        ] {
            assert!(stream.contains(sent), "{sent} was sent: {stream}");
        }
        served.push(stream);
        served.push(page(fixture, browser, &run).await?);
        finish(fixture, browser, &run, ("keep", &[])).await?;
        let report = page(fixture, browser, &run).await?;
        assert!(
            report.contains("<th scope=\"row\" class=\"mono\">Wireguard0</th>"),
            "the report lists the tunnel's new public key: {report}"
        );
        served.push(report);
        Ok(run)
    }

    #[tokio::test]
    async fn no_secret_value_reaches_a_user_without_reveal_secrets() -> TestResult {
        let fixture = setup::fixture().await?;
        let key = format!("{}=", "S".repeat(43));
        let tunnel = format!("interface Wireguard0 wireguard private-key {key}");
        let user = format!("user alice password plain {SOURCE_PASSWORD}");
        seed(&fixture, "prod-1", &[DNS_LINES[0], &tunnel, &user]).await?;
        let startup = fixture.router("prod-1")?.startup_config_text();
        let encoded = word_after(&startup, "private-key ns3 ")?;
        let hash = word_after(&startup, "password md5 ")?;
        let secrets = [
            key.as_str(),
            encoded.as_str(),
            hash.as_str(),
            SOURCE_PASSWORD,
            TARGET_PASSWORD,
        ];
        let migrator = fixture.login("migrator").await?;
        let mut served = Vec::new();
        let id = captured(&fixture, &migrator, &mut served).await?;
        let refused = fixture
            .post_form(&format!("/ui/presets/{id}/reveal"), &migrator, &[])
            .await?;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN, "no Reveal");
        let run = applied(&fixture, &migrator, &id, &mut served).await?;
        assert!(
            !fixture
                .router("lab-1")?
                .running_config_text()
                .contains(&encoded),
            "the target made its own key; the captured one was not copied"
        );
        for file in ["report.json", "report.md"] {
            served.push(page(&fixture, &migrator, &format!("{run}/download/{file}")).await?);
        }
        assert!(
            served
                .iter()
                .any(|body| body.contains("wireguard private-key"))
                && served
                    .iter()
                    .any(|body| body.contains("user alice password")),
            "the secret-bearing settings were shown, redacted"
        );
        for (index, body) in served.iter().enumerate() {
            for secret in secrets {
                assert!(!body.contains(secret), "response {index} holds a secret");
            }
        }
        for (path, content) in files(&fixture.state_dir())? {
            for secret in secrets {
                assert!(!content.contains(secret), "{path} holds a secret");
            }
        }
        let admin = fixture.login("admin").await?;
        let revealed = fixture
            .post_form(&format!("/ui/presets/{id}/reveal"), &admin, &[])
            .await?;
        assert!(
            text(revealed).await?.contains(&encoded),
            "Reveal shows the stored value to a role with RevealSecrets"
        );
        assert_eq!(
            fixture.outcomes("web.preset_reveal")?,
            ["forbidden", "shown"]
        );
        Ok(())
    }
}
