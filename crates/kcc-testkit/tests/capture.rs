//! `kcc-capture` against the fake router: planted identifiers never reach the output, the
//! self-check refuses a leaked one, and `--identifiers-out` lists every learned one.

#[cfg(test)]
#[path = "capture/fidelity.rs"]
mod fidelity;
#[cfg(test)]
#[path = "capture/hardening.rs"]
mod hardening;
#[cfg(test)]
#[path = "capture/leaks.rs"]
mod leaks;
#[cfg(test)]
#[path = "capture/spellings.rs"]
mod spellings;

#[cfg(test)]
#[expect(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
mod tests {
    use core::{error::Error, fmt, fmt::Write as _, net::SocketAddr};
    use std::{
        fs,
        path::{Path, PathBuf},
        process::{Command, Output},
    };

    use axum::http::Method;
    use kcc_testkit::{DEFAULT_PASSWORD, FakeRouter, Handle, RequestRecord, model::Profile};
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::task::spawn_blocking;

    /// Test result.
    pub(super) type TestResult = Result<(), Box<dyn Error>>;

    /// Serial of the fake router.
    pub(super) const SERIAL: &str = "S0000000000001";

    /// Planted values, one per anonymizer rule; none may reach a written file.
    pub(super) const NAME: &str = "PLANTED-HOST-7";
    /// Planted `known-host`.
    const KNOWN_HOST: &str = "PLANTED-KNOWN-8";
    /// Planted `fqdn`.
    const FQDN: &str = "planted-fqdn-9.example";
    /// Planted `http-host`.
    const HTTP_HOST: &str = "planted-http-10.example";
    /// Planted `booked`.
    const BOOKED: &str = "PLANTED-BOOKED-11";
    /// Planted `cid`.
    const CID: &str = "PLANTED-CID-12";
    /// Planted `show rc user` key.
    pub(super) const USER: &str = "PLANTED-USER-13";

    /// Every planted value.
    const PLANTED: [&str; 7] = [NAME, KNOWN_HOST, FQDN, HTTP_HOST, BOOKED, CID, USER];

    /// A fake router holding every planted value.
    pub(super) async fn planted_router() -> Result<(SocketAddr, Handle), Box<dyn Error>> {
        let row = json!({
            "mac": "02:00:00:00:07:01", "ip": "192.0.2.77", "name": NAME,
            "known-host": KNOWN_HOST, "fqdn": FQDN, "http-host": HTTP_HOST,
            "booked": BOOKED, "cid": CID,
        });
        let served = FakeRouter::builder(Profile::default())
            .show_fixture("ip/arp", json!([row]))
            .rc_fixture("/user", json!({USER: {"tag": ["cli"]}}))
            .build()?
            .serve(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await?;
        Ok(served)
    }

    /// Runs `kcc-capture` against `address`, writing below `scratch/out`.
    #[expect(
        clippy::disallowed_methods,
        reason = "the test runs the kcc-capture binary itself: its exit status is the contract"
    )]
    pub(super) async fn run_capture(
        address: SocketAddr,
        scratch: &Path,
        extra: &[String],
    ) -> Result<Output, Box<dyn Error>> {
        let password = scratch.join("password");
        fs::write(&password, format!("{DEFAULT_PASSWORD}\n"))?;
        let mut command = Command::new(env!("CARGO_BIN_EXE_kcc-capture"));
        let _: &mut Command = command
            .arg("--url")
            .arg(format!("http://{address}"))
            .arg("--password-file")
            .arg(&password)
            .arg("--allow-serial")
            .arg(SERIAL)
            .arg("--out")
            .arg(scratch.join("out"))
            .arg("--allow-loopback")
            .args(extra);
        Ok(spawn_blocking(move || command.output()).await??)
    }

    /// The text of every file below `root`, lowercased.
    pub(super) fn all_text(root: &Path) -> Result<String, Box<dyn Error>> {
        let mut text = String::new();
        let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                for entry in fs::read_dir(&path)? {
                    pending.push(entry?.path());
                }
            } else {
                text.push_str(&fs::read_to_string(&path)?.to_lowercase());
            }
        }
        Ok(text)
    }

    /// Whether `record` is a request the capture may send.
    fn allowed(record: &RequestRecord) -> bool {
        let path = record.path();
        match *record.method() {
            Method::GET => {
                path.starts_with("/rci/show/")
                    || matches!(
                        path,
                        "/rci/whoami"
                            | "/rci/"
                            | "/auth"
                            | "/rci/components/list"
                            | "/rci/components/preview"
                            | "/rci/tools/ping"
                    )
                    || path == "/ci/running-config.txt"
            }
            Method::POST => matches!(
                path,
                "/rci/"
                    | "/rci/show/log"
                    | "/rci/components/list"
                    | "/rci/components/preview"
                    | "/rci/tools/ping"
                    | "/auth"
            ),
            Method::DELETE => path == "/auth",
            _ => false,
        }
    }

    /// Planted identifiers stay out of the output and go to `--identifiers-out` (todo 4).
    ///
    /// Planted names, hosts, cids and `show rc user` keys never reach the written files;
    /// `--identifiers-out` lists each of them in a 0600 file; the capture sends only reads,
    /// the self-ping and the components reads, and signs out after the log stream.
    #[tokio::test(flavor = "multi_thread")]
    async fn capture_hides_planted_values_and_lists_them_in_identifiers_out() -> TestResult {
        let (address, handle) = planted_router().await?;
        let scratch = TempDir::new()?;
        let identifiers = scratch.path().join("identifiers.txt");
        let output = run_capture(
            address,
            scratch.path(),
            &[
                "--identifiers-out".to_owned(),
                identifiers.display().to_string(),
            ],
        )
        .await?;
        let log = handle.request_log();
        handle.shutdown().await?;
        assert!(output.status.success(), "{output:?}");
        let written = all_text(&scratch.path().join("out"))?;
        for planted in PLANTED {
            assert!(
                !written.contains(&planted.to_lowercase()),
                "a planted value survived"
            );
        }
        for expected in [
            "components-list",
            "components-preview",
            "tools-ping",
            "show-log-stream",
        ] {
            assert!(written.contains(expected), "{expected} in the manifest");
        }
        let listed = fs::read_to_string(&identifiers)?;
        for planted in PLANTED {
            assert!(
                listed.lines().any(|line| line == planted),
                "{planted} in identifiers"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&identifiers)?.permissions().mode() & 0o777,
                0o600,
                "identifiers file mode"
            );
        }
        let refused: Vec<String> = log
            .iter()
            .filter(|record| !allowed(record))
            .map(|record| format!("{} {}", record.method(), record.path()))
            .collect();
        assert!(refused.is_empty(), "unexpected requests: {refused:?}");
        let position = |method: &Method, path: &str| {
            log.iter()
                .position(|record| record.method() == method && record.path() == path)
        };
        let stream = position(&Method::POST, "/rci/show/log");
        let sign_out = position(&Method::DELETE, "/auth");
        assert!(
            stream.is_some() && sign_out > stream,
            "the session is signed out after the log stream"
        );
        assert!(
            position(&Method::POST, "/rci/tools/ping").is_some(),
            "self-ping"
        );
        Ok(())
    }

    /// A leaked learned name makes the capture delete its output and exit 3 (todo 4).
    ///
    /// The anonymizer does not rewrite a percent-encoded copy of a learned name in a log
    /// line; the self-check finds it and names the item, never the value.
    #[tokio::test(flavor = "multi_thread")]
    async fn self_check_removes_output_and_exits_3_on_a_leaked_name() -> TestResult {
        let (address, handle) = planted_router().await?;
        handle.insert_log(
            1,
            json!({"message": {"label": "I", "message": format!("dhcp: lease for {}", percent_encoded(NAME)?)}}),
        );
        let scratch = TempDir::new()?;
        let identifiers = scratch.path().join("identifiers.txt");
        let output = run_capture(
            address,
            scratch.path(),
            &[
                "--identifiers-out".to_owned(),
                identifiers.display().to_string(),
            ],
        )
        .await?;
        handle.shutdown().await?;
        assert_eq!(output.status.code(), Some(3_i32), "{output:?}");
        let out = scratch.path().join("out");
        let remaining = if out.exists() {
            fs::read_dir(&out)?.count()
        } else {
            0_usize
        };
        assert_eq!(remaining, 0, "the capture directory is removed");
        assert!(
            !identifiers.exists(),
            "nothing is written outside the capture"
        );
        let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
        assert!(stderr.contains("show-log"), "the item is named: {stderr}");
        assert!(
            !stderr.contains(&NAME.to_lowercase()),
            "the value is never printed"
        );
        Ok(())
    }

    /// `text` with every byte percent-encoded.
    pub(super) fn percent_encoded(text: &str) -> Result<String, fmt::Error> {
        let mut encoded = String::new();
        for byte in text.bytes() {
            write!(encoded, "%{byte:02X}")?;
        }
        Ok(encoded)
    }

    /// `--identifiers-out` inside the capture directory is refused before anything is
    /// written (todo 4).
    #[tokio::test(flavor = "multi_thread")]
    async fn identifiers_out_inside_the_capture_directory_is_refused() -> TestResult {
        let (address, handle) = planted_router().await?;
        let scratch = TempDir::new()?;
        let inside = scratch.path().join("out/KN-1811-5.1.3/identifiers.txt");
        let output = run_capture(
            address,
            scratch.path(),
            &["--identifiers-out".to_owned(), inside.display().to_string()],
        )
        .await?;
        handle.shutdown().await?;
        assert!(!output.status.success(), "{output:?}");
        assert!(!inside.exists(), "no identifiers file is written");
        assert!(
            !scratch
                .path()
                .join("out/KN-1811-5.1.3/manifest.json")
                .exists(),
            "no capture is written"
        );
        Ok(())
    }
}
