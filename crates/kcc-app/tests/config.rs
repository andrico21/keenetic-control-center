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

    use alloc::collections::{BTreeMap, BTreeSet};
    use core::{cell::RefCell, error::Error, time::Duration};
    use std::{env, path::PathBuf};

    use kcc_app::settings::{
        ClientLabel, Config, ConfigError, KCC_ENV_VARS, RouterAuth, RouterTls, default_state_dir,
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

    /// The override pass reads exactly the documented `KCC_ENV_VARS`.
    #[test]
    fn every_documented_env_var_is_read() -> TestResult {
        let seen = RefCell::new(BTreeSet::new());
        let mut config = Config::from_toml_str("")?;
        drop(config.apply_kcc_env_overrides_with(|var| {
            let _: bool = seen.borrow_mut().insert(var.to_owned());
            Ok(None)
        })?);
        let documented: BTreeSet<String> =
            KCC_ENV_VARS.iter().map(|var| (*var).to_owned()).collect();
        assert_eq!(
            seen.into_inner(),
            documented,
            "read set equals KCC_ENV_VARS"
        );
        Ok(())
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
