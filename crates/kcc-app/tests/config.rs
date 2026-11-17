//! `kcc.toml` schema tests: defaults, unknown keys, validation, env overrides.

#[cfg(test)]
#[expect(clippy::panic_in_result_fn, reason = "a test fails by panicking")]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
#[expect(
    clippy::missing_panics_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    extern crate alloc;

    use alloc::collections::BTreeMap;
    use core::{error::Error, time::Duration};
    use std::{
        env,
        path::{Path, PathBuf},
    };

    use kcc_app::settings::{
        ClientLabel, Config, ConfigError, LogMode, LogSinkConfig, RouterAuth, RouterTls,
        SearchFlavor, default_state_dir,
    };
    use url::Url;

    /// Test result.
    type TestResult = Result<(), Box<dyn Error>>;

    /// A router entry that validates.
    const ROUTER: &str = r#"
[[routers]]
name = "home"
url = "http://192.168.1.1"
login = "admin"
password_file = "/etc/kcc/home.pw"
"#;

    /// Parses `text` and expects a parse error mentioning `needle`.
    fn expect_parse_error(text: &str, needle: &str) -> TestResult {
        match Config::from_toml_str(text) {
            Err(ConfigError::Parse(error)) => {
                let message = error.to_string();
                assert!(
                    message.contains(needle),
                    "error for {needle:?} does not name it: {message}"
                );
                Ok(())
            }
            Err(other) => Err(format!("expected a parse error for {needle:?}, got {other}").into()),
            Ok(_) => Err(format!("config with unknown {needle:?} was accepted").into()),
        }
    }

    /// Parses `text` and expects validation to fail on `field`.
    fn expect_invalid(text: &str, field: &str) -> TestResult {
        match Config::from_toml_str(text)?.validate() {
            Err(ConfigError::Invalid {
                field: found,
                reason: _,
            }) => {
                assert_eq!(found, field, "wrong field reported");
                Ok(())
            }
            other => Err(format!("expected invalid {field}, got {other:?}").into()),
        }
    }

    /// An empty file yields the documented defaults and validates.
    #[test]
    fn empty_file_gives_documented_defaults() -> TestResult {
        let config = Config::from_toml_str("")?;
        config.validate()?;
        assert_eq!(
            config.web_allowed_origins()?,
            [
                "http://127.0.0.1:8443",
                "http://[::1]:8443",
                "http://localhost:8443",
            ],
            "loopback aliases are accepted automatically"
        );
        assert!(config.web.enabled, "web enabled by default");
        assert_eq!(
            config.web.session_idle,
            Duration::from_mins(30),
            "session_idle"
        );
        assert_eq!(
            config.web.session_absolute,
            Duration::from_hours(12),
            "session_absolute"
        );
        assert_eq!(config.web.login_max_failures, 5, "login_max_failures");
        assert_eq!(config.web.lockout, Duration::from_mins(15), "lockout");
        assert_eq!(config.web.default_locale, "en", "default_locale");
        assert!(config.mcp.http_enabled, "http_enabled");
        assert!(!config.mcp.stdio_enabled, "stdio_enabled");
        assert_eq!(config.mcp.stdio_role, "viewer", "stdio_role");
        assert!(!config.mcp.read_only, "read_only");
        assert!(!config.mcp.allow_destructive, "allow_destructive");
        assert_eq!(config.mcp.max_result_bytes, 32 * 1024, "max_result_bytes");
        assert_eq!(config.mcp.toolsets, ["core"], "toolsets");
        assert!(!config.outbound.allow_loopback, "allow_loopback");
        assert_eq!(config.state.dir, None, "state dir");
        assert_eq!(config.backups.keep_last, 50, "keep_last");
        assert_eq!(
            config.backups.max_age,
            Duration::from_hours(180 * 24),
            "max_age"
        );
        assert_eq!(
            config.audit.retention,
            Duration::from_hours(365 * 24),
            "retention"
        );
        assert_eq!(config.cli.role, "admin", "cli role");
        assert!(config.cli.router_scope.is_empty(), "router_scope");
        assert!(
            !config.privacy.redact_clients_in_mcp,
            "redact_clients_in_mcp"
        );
        assert!(config.routers.is_empty(), "routers");
        Ok(())
    }

    #[test]
    fn logs_defaults_are_disabled_and_bounded() -> TestResult {
        let config = Config::from_toml_str("")?;
        assert!(!config.logs.enabled, "logs off by default");
        assert_eq!(config.logs.mode, LogMode::Stream, "stream mode default");
        assert_eq!(config.logs.stream_interval, Duration::from_secs(5));
        assert_eq!(config.logs.poll_interval, Duration::from_secs(30));
        assert_eq!(config.logs.queue_max, 10_000);
        assert!(config.logs.routers.is_empty(), "all routers by default");
        assert!(config.logs.sinks.is_empty(), "no sinks by default");
        Ok(())
    }

    #[test]
    fn web_transport_refuses_non_loopback_plain_http() -> TestResult {
        expect_invalid("[server]\nlisten_addr = \"0.0.0.0\"", "server.listen_addr")?;

        let proxied = Config::from_toml_str(
            r#"
[server]
listen_addr = "0.0.0.0"
trusted_proxies = ["127.0.0.1/32"]

[web]
public_url = "https://kcc.example.net/app"
"#,
        )?;
        proxied.validate()?;
        assert_eq!(
            proxied.web_allowed_origins()?,
            ["https://kcc.example.net"],
            "public URL is normalized to an origin"
        );
        Ok(())
    }

    /// `SEC1-03` / `F-03`: the Web cookie and CSP follow the browser-facing transport, which
    /// is TLS at the listener or an `https` public URL behind a trusted proxy.
    #[test]
    fn browser_transport_is_secure_for_listener_tls_or_an_https_public_url() -> TestResult {
        let plain = Config::from_toml_str("")?;
        assert!(!plain.listener_tls(), "default listener is plain");
        assert!(!plain.browser_transport_secure(), "default is plain HTTP");

        let http_url = Config::from_toml_str(
            "[server]\ntrusted_proxies = [\"127.0.0.1/32\"]\n[web]\npublic_url = \"http://kcc.example.net/\"\n",
        )?;
        assert!(
            !http_url.browser_transport_secure(),
            "an http public URL stays plain"
        );

        let proxied = Config::from_toml_str(
            "[server]\ntrusted_proxies = [\"127.0.0.1/32\"]\n[web]\npublic_url = \"https://kcc.example.net/\"\n",
        )?;
        assert!(!proxied.listener_tls(), "the listener itself stays plain");
        assert!(
            proxied.browser_transport_secure(),
            "an https public URL makes the browser transport secure"
        );

        let listener = Config::from_toml_str(
            "[server]\ntls_cert_path = \"/etc/kcc/tls.crt\"\ntls_key_path = \"/etc/kcc/tls.key\"\n",
        )?;
        assert!(listener.listener_tls());
        assert!(listener.browser_transport_secure());

        let half = Config::from_toml_str("[server]\ntls_cert_path = \"/etc/kcc/tls.crt\"\n")?;
        assert!(
            !half.listener_tls(),
            "a certificate without a key is not TLS"
        );
        Ok(())
    }

    /// A config using every section parses into the expected values.
    #[test]
    fn full_config_parses_and_validates() -> TestResult {
        let text = r#"
[server]
listen_addr = "127.0.0.1"
listen_port = 8443

[observability]
log_level = "info"

[web]
enabled = false
session_idle = "10m"
public_url = "https://kcc.example.net/"

[mcp]
read_only = true
max_result_bytes = 4096

[outbound]
allowed_networks = ["192.168.0.0/16", "fd00::/8"]
allowed_suffixes = [".lan"]
allow_loopback = true

[state]
dir = "/var/lib/kcc"

[backups]
keep_last = 7
max_age = "30d"

[audit]
retention = "90d"

[cli]
role = "viewer"
router_scope = ["home-*"]

[privacy]
redact_clients_in_mcp = true

[[routers]]
name = "home"
url = "http://192.168.1.1"
login = "admin"
password_file = "/etc/kcc/home.pw"
auth = "ndw2"
test_device = true
tags = ["lab"]

[[routers]]
name = "office"
url = "https://office.lan"
token_file = "/etc/kcc/office.token"
auth = "token"
tls = { pin_sha256 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" }
"#;
        let config = Config::from_toml_str(text)?;
        config.validate()?;
        assert!(!config.web.enabled, "web.enabled");
        assert_eq!(
            config.web.session_idle,
            Duration::from_mins(10),
            "session_idle"
        );
        assert_eq!(
            config.web.public_url.as_ref().map(Url::as_str),
            Some("https://kcc.example.net/"),
            "public_url"
        );
        assert_eq!(
            config.outbound.allowed_networks.len(),
            2,
            "allowed_networks"
        );
        assert_eq!(
            config.state.dir,
            Some(PathBuf::from("/var/lib/kcc")),
            "state dir"
        );
        assert_eq!(
            config.backups.max_age,
            Duration::from_hours(30 * 24),
            "max_age"
        );
        let [home, office] = config.routers.as_slice() else {
            return Err("expected two routers".into());
        };
        assert_eq!(home.auth, RouterAuth::Ndw2, "home auth");
        assert_eq!(home.tls, RouterTls::Verify, "home tls default");
        assert!(home.test_device, "home test_device");
        assert_eq!(office.auth, RouterAuth::Token, "office auth");
        assert!(
            matches!(&office.tls, RouterTls::PinSha256(pin) if pin.len() == 64),
            "office pin"
        );
        Ok(())
    }

    #[test]
    fn outbound_suffixes_are_normalized_when_loaded() -> TestResult {
        let config = Config::from_toml_str(
            "[outbound]\nallowed_suffixes = [\"keenetic.pro\", \".ROUTER.Example\"]",
        )?;

        assert_eq!(
            config.outbound.allowed_suffixes,
            [".keenetic.pro", ".router.example"]
        );
        Ok(())
    }

    #[test]
    fn invalid_outbound_suffixes_are_rejected_when_loaded() {
        for suffix in [
            "",
            ".",
            "bad..example",
            "-bad.example",
            "bad-.example",
            "bad/example",
        ] {
            let text = format!("[outbound]\nallowed_suffixes = [{suffix:?}]");
            assert!(
                matches!(
                    Config::from_toml_str(&text),
                    Err(ConfigError::Invalid { field, reason: _ })
                        if field == "outbound.allowed_suffixes"
                ),
                "accepted invalid suffix {suffix:?}"
            );
        }
    }

    /// A-14: `[outbound] argon2_max_iterations` loads only inside 1..=64, the protocol range.
    #[test]
    fn argon2_iteration_cap_outside_protocol_range_is_refused_at_load() -> TestResult {
        for value in [1_u32, 16, 64] {
            drop(Config::from_toml_str(&format!(
                "[outbound]\nargon2_max_iterations = {value}"
            ))?);
        }
        for value in [0_u32, 65] {
            let text = format!("[outbound]\nargon2_max_iterations = {value}");
            assert!(
                matches!(
                    Config::from_toml_str(&text),
                    Err(ConfigError::Invalid { field, reason: _ })
                        if field == "outbound.argon2_max_iterations"
                ),
                "accepted {value}"
            );
        }
        Ok(())
    }

    /// The `[serverr]` typo is rejected with an error naming the table.
    #[test]
    fn misspelled_server_table_is_rejected() -> TestResult {
        expect_parse_error("[serverr]\nlisten_port = 8443\n", "unknown field `serverr`")
    }

    #[test]
    fn privileged_listener_ports_are_rejected() -> TestResult {
        expect_invalid(
            "[server]\nlisten_addr = \"0.0.0.0\"\nlisten_port = 443\n",
            "server.listen_port",
        )?;
        expect_invalid(
            "[observability]\nmetrics_enabled = true\nmetrics_bind = \"127.0.0.1:443\"\n",
            "observability.metrics_bind",
        )
    }

    /// An unknown key in any section is rejected with an error naming it.
    #[test]
    fn unknown_key_in_every_section_is_rejected() -> TestResult {
        let sections = [
            "server",
            "observability",
            "web",
            "mcp",
            "outbound",
            "state",
            "backups",
            "audit",
            "cli",
            "privacy",
            "metrics",
            "logs",
        ];
        for section in sections {
            expect_parse_error(&format!("[{section}]\nbogus_key = 1\n"), "bogus_key")?;
        }
        expect_parse_error(&format!("{ROUTER}bogus_key = 1\n"), "bogus_key")?;
        expect_parse_error("bogus_root = 1\n", "bogus_root")?;
        expect_parse_error(&format!("{ROUTER}auth = \"basic\"\n"), "basic")?;
        expect_parse_error(&format!("{ROUTER}tls = \"skip\"\n"), "skip")
    }

    /// Cross-field router rules are enforced and name the field.
    #[test]
    fn invalid_router_profiles_are_rejected() -> TestResult {
        expect_invalid(
            &format!("{ROUTER}token_file = \"/t\"\n"),
            "routers.home.password_file",
        )?;
        expect_invalid(
            &format!("{ROUTER}tls = {{ pin_sha256 = \"abc\" }}\n"),
            "routers.home.tls.pin_sha256",
        )?;
        expect_invalid(&format!("{ROUTER}{ROUTER}"), "routers.home.name")?;
        expect_invalid(
            &ROUTER.replace("http://192.168.1.1", "ftp://192.168.1.1"),
            "routers.home.url",
        )?;
        expect_invalid(
            &ROUTER.replace("login = \"admin\"\n", ""),
            "routers.home.login",
        )?;
        expect_invalid(&ROUTER.replace("\"home\"", "\"../x\""), "routers.name")
    }

    /// Router names must follow the registry rule: 1-32 characters, lowercase letters, digits and `-`.
    /// Uppercase letters (e.g., `Home.1`) are rejected. Names over 32 characters are rejected.
    #[test]
    fn router_name_must_follow_registry_rule() -> TestResult {
        // Uppercase is not allowed in router names (registry rule is [a-z0-9-] only).
        expect_invalid(&ROUTER.replace("\"home\"", "\"Home.1\""), "routers.name")?;
        // 40-character name exceeds the 32-character limit.
        expect_invalid(
            &ROUTER.replace("\"home\"", "\"this-is-a-very-long-router-name-of-40x\""),
            "routers.name",
        )?;
        // A valid lowercase hyphenated name passes.
        let config = Config::from_toml_str(&ROUTER.replace("\"home\"", "\"home-1\""))?;
        config.validate()?;
        Ok(())
    }

    /// `logs.routers` entries must use the same router-name rule as the registry.
    #[test]
    fn logs_routers_must_follow_registry_rule() -> TestResult {
        let config_with_bad_log_router = format!("{ROUTER}\n[logs]\nrouters = [\"Home.1\"]");
        expect_invalid(&config_with_bad_log_router, "logs.routers")?;
        Ok(())
    }

    /// `[metrics]` defaults are off, loopback, pseudonymous and within the IS-13 floors;
    /// every unsafe or overloading value is refused naming its field.
    #[test]
    fn metrics_section_defaults_and_limits() -> TestResult {
        let config = Config::from_toml_str("")?;
        let metrics = &config.metrics;
        assert!(!metrics.enabled, "metrics off by default");
        assert_eq!(metrics.bind.to_string(), "127.0.0.1:9090", "bind");
        assert!(!metrics.allow_non_loopback, "allow_non_loopback");
        assert_eq!(metrics.interval, Duration::from_secs(30), "interval");
        assert_eq!(
            metrics.heavy_interval,
            Duration::from_secs(120),
            "heavy_interval"
        );
        assert!(!metrics.per_client, "no per-client series by default");
        assert_eq!(metrics.per_client_max, 256, "per_client_max");
        assert_eq!(
            metrics.per_client_label,
            ClientLabel::Pseudonym,
            "per_client_label"
        );
        expect_invalid("[metrics]\ninterval = \"14s\"\n", "metrics.interval")?;
        expect_invalid(
            "[metrics]\nheavy_interval = \"59s\"\n",
            "metrics.heavy_interval",
        )?;
        expect_invalid("[metrics]\nbind = \"127.0.0.1:443\"\n", "metrics.bind")?;
        expect_invalid("[metrics]\nbind = \"0.0.0.0:9090\"\n", "metrics.bind")?;
        expect_invalid("[metrics]\nper_client_max = 0\n", "metrics.per_client_max")?;
        expect_invalid(
            "[observability]\nmetrics_enabled = true\n[metrics]\nenabled = true\n",
            "observability.metrics_enabled",
        )?;
        expect_parse_error("[metrics]\nper_client_label = \"ip\"\n", "ip")?;
        let open = Config::from_toml_str(
            "[metrics]\nenabled = true\nbind = \"0.0.0.0:9090\"\nallow_non_loopback = true\nper_client_label = \"mac\"\n",
        )?;
        open.validate()?;
        assert_eq!(open.metrics.per_client_label, ClientLabel::Mac, "mac label");
        Ok(())
    }

    /// `KCC_METRICS_*` overrides replace the `[metrics]` values.
    #[test]
    fn kcc_metrics_env_overrides_apply() -> TestResult {
        let env = BTreeMap::from([
            ("KCC_METRICS_ENABLED", "1"),
            ("KCC_METRICS_BIND", "127.0.0.1:19090"),
            ("KCC_METRICS_INTERVAL", "45s"),
            ("KCC_METRICS_PER_CLIENT", "true"),
            ("KCC_METRICS_PER_CLIENT_MAX", "3"),
            ("KCC_METRICS_PER_CLIENT_LABEL", "name"),
        ]);
        let mut config = Config::from_toml_str("")?;
        drop(config.apply_kcc_env_overrides_with(|var| {
            Ok(env.get(var).map(|value| (*value).to_owned()))
        })?);
        config.validate()?;
        assert!(config.metrics.enabled, "enabled");
        assert_eq!(config.metrics.bind.port(), 19090, "bind");
        assert_eq!(config.metrics.interval, Duration::from_secs(45), "interval");
        assert!(config.metrics.per_client, "per_client");
        assert_eq!(config.metrics.per_client_max, 3, "per_client_max");
        assert_eq!(config.metrics.per_client_label, ClientLabel::Name, "label");
        Ok(())
    }

    #[test]
    fn logs_section_parses_and_validates_sink_boundaries() -> TestResult {
        let config = Config::from_toml_str(
            r#"
[logs]
enabled = true
routers = ["home"]
mode = "poll"
stream_interval = "6s"
poll_interval = "45s"
redact_macs = true
queue_max = 321

[[logs.sinks]]
kind = "loki"
url = "http://127.0.0.1:3100"
tenant = "lab"
basic_auth_user = "collector"
password_file = "/run/secrets/loki"
compress = true

[[logs.sinks]]
kind = "elasticsearch"
url = "https://search.example.net/base/"
flavor = "opensearch"
api_key_file = "/run/secrets/search"
ca_file = "/etc/kcc/search-ca.pem"

[[logs.sinks]]
kind = "stdout"
"#,
        )?;
        config.validate()?;
        assert_eq!(config.logs.mode, LogMode::Poll);
        assert!(config.logs.redact_macs);
        assert_eq!(config.logs.queue_max, 321);
        let [
            LogSinkConfig::Loki {
                password_file,
                url: _,
                tenant: _,
                basic_auth_user: _,
                bearer_token_file: _,
                ca_file: _,
                compress: _,
            },
            LogSinkConfig::Elasticsearch {
                flavor,
                api_key_file,
                url: _,
                target: _,
                basic_auth_user: _,
                password_file: _,
                ca_file: _,
                compress: _,
            },
            LogSinkConfig::Stdout,
        ] = config.logs.sinks.as_slice()
        else {
            return Err("unexpected sink variants".into());
        };
        assert_eq!(
            password_file.as_deref(),
            Some(Path::new("/run/secrets/loki"))
        );
        assert_eq!(*flavor, SearchFlavor::Opensearch);
        assert_eq!(
            api_key_file.as_deref(),
            Some(Path::new("/run/secrets/search"))
        );

        expect_invalid("[logs]\nstream_interval = \"4s\"\n", "logs.stream_interval")?;
        expect_invalid("[logs]\npoll_interval = \"4s\"\n", "logs.poll_interval")?;
        expect_invalid("[logs]\nqueue_max = 0\n", "logs.queue_max")?;
        expect_invalid(
            "[[logs.sinks]]\nkind = \"loki\"\nurl = \"http://192.0.2.1:3100\"\n",
            "logs.sinks.0.url",
        )?;
        expect_invalid(
            "[[logs.sinks]]\nkind = \"loki\"\nurl = \"https://logs.example\"\nbasic_auth_user = \"u\"\npassword_file = \"/p\"\nbearer_token_file = \"/t\"\n",
            "logs.sinks.0.password_file",
        )
    }

    #[test]
    fn kcc_logs_env_overrides_apply() -> TestResult {
        let env = BTreeMap::from([
            ("KCC_LOGS_ENABLED", "1"),
            ("KCC_LOGS_ROUTERS", "home,lab"),
            ("KCC_LOGS_MODE", "poll"),
            ("KCC_LOGS_STREAM_INTERVAL", "7s"),
            ("KCC_LOGS_POLL_INTERVAL", "35s"),
            ("KCC_LOGS_REDACT_MACS", "true"),
            ("KCC_LOGS_QUEUE_MAX", "654"),
        ]);
        let mut config = Config::from_toml_str("")?;
        drop(config.apply_kcc_env_overrides_with(|var| {
            Ok(env.get(var).map(|value| (*value).to_owned()))
        })?);
        config.validate()?;
        assert!(config.logs.enabled);
        assert_eq!(config.logs.routers, ["home", "lab"]);
        assert_eq!(config.logs.mode, LogMode::Poll);
        assert_eq!(config.logs.stream_interval, Duration::from_secs(7));
        assert_eq!(config.logs.poll_interval, Duration::from_secs(35));
        assert!(config.logs.redact_macs);
        assert_eq!(config.logs.queue_max, 654);
        Ok(())
    }

    /// `KCC_*` overrides replace values and are reported.
    #[test]
    fn kcc_env_overrides_apply_and_report() -> TestResult {
        let env = BTreeMap::from([
            ("KCC_WEB_SESSION_IDLE", "45m"),
            ("KCC_MCP_READ_ONLY", "true"),
            ("KCC_MCP_STDIO_ROLE", "operator"),
            ("KCC_MCP_TOOLSETS", "core, network-write"),
            (
                "KCC_OUTBOUND_ALLOWED_NETWORKS",
                "192.168.1.0/24, 10.0.0.0/8",
            ),
            ("KCC_STATE_DIR", "/srv/kcc"),
            ("KCC_CLI_ROUTER_SCOPE", "a,b"),
        ]);
        let mut config = Config::from_toml_str("")?;
        let report = config.apply_kcc_env_overrides_with(|var| {
            Ok(env.get(var).map(|value| (*value).to_owned()))
        })?;
        assert_eq!(
            config.web.session_idle,
            Duration::from_mins(45),
            "session_idle"
        );
        assert!(config.mcp.read_only, "read_only");
        assert_eq!(config.mcp.stdio_role, "operator", "stdio_role");
        assert_eq!(config.mcp.toolsets, ["core", "network-write"], "toolsets");
        assert_eq!(
            config.outbound.allowed_networks.len(),
            2,
            "allowed_networks"
        );
        assert_eq!(
            config.state.dir,
            Some(PathBuf::from("/srv/kcc")),
            "state dir"
        );
        assert_eq!(config.cli.router_scope, ["a", "b"], "router_scope");
        let fields: Vec<&str> = report
            .iter()
            .map(|entry| entry.target_field.as_str())
            .collect();
        assert_eq!(
            fields,
            [
                "web.session_idle",
                "mcp.stdio_role",
                "mcp.read_only",
                "mcp.toolsets",
                "outbound.allowed_networks",
                "state.dir",
                "cli.router_scope"
            ],
            "report lists applied overrides in order"
        );
        Ok(())
    }

    /// A malformed `KCC_*` value is an error naming the variable.
    #[test]
    fn bad_kcc_env_value_is_rejected() -> TestResult {
        let mut config = Config::from_toml_str("")?;
        let result = config.apply_kcc_env_overrides_with(|var| {
            Ok((var == "KCC_MCP_READ_ONLY").then(|| "yes".to_owned()))
        });
        match result {
            Err(ConfigError::Env { var, reason: _ }) => {
                assert_eq!(var, "KCC_MCP_READ_ONLY", "variable named");
                Ok(())
            }
            other => Err(format!("expected an env error, got {other:?}").into()),
        }
    }

    /// Linux default: `$XDG_STATE_HOME/kcc`, else `~/.local/state/kcc`.
    /// The Windows (`%LOCALAPPDATA%\kcc`) and macOS
    /// (`~/Library/Application Support/kcc`) branches are not exercised on
    /// this host.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_default_state_dir_follows_xdg() -> TestResult {
        let base = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| env::home_dir().map(|home| home.join(".local/state")))
            .ok_or("no HOME")?;
        assert_eq!(default_state_dir(), Some(base.join("kcc")), "state dir");
        let config = Config::from_toml_str("")?;
        assert_eq!(config.state.resolved_dir()?, base.join("kcc"), "resolved");
        Ok(())
    }
}
