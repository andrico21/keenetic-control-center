//! The MCP settings resolver: precedence, planning without writing, refusals, the role
//! ceiling, safety-reducing changes, and concurrent saves.

#[cfg(test)]
#[path = "mcp_settings/ceiling.rs"]
mod ceiling;

#[cfg(test)]
#[expect(
    clippy::missing_panics_doc,
    clippy::panic_in_result_fn,
    reason = "test assertions deliberately panic and are not rendered API documentation"
)]
#[expect(
    clippy::missing_errors_doc,
    reason = "test code is not rendered API documentation"
)]
mod tests {
    use core::{error::Error, net::IpAddr};
    use std::fs;

    use kcc_app::{
        mcp_settings::{
            EnvOverrides, McpBase, SettingsError, Source, commit,
            document::{McpOverrides, McpSettingsDocument},
            effective,
            keys::KeyPath,
        },
        permissions::{Permission, Role, RolesDocument},
        persist::{StateDoc as _, StateStore},
        settings::{
            Config, ConfigError,
            mcp_schema::{MtlsMode, ScopeMapping},
        },
    };
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn Error>>;

    /// A fresh state directory.
    fn store() -> Result<(TempDir, StateStore), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let state = StateStore::open(&temp.path().join("state"))?;
        Ok((temp, state))
    }

    /// The registry's answer: `raw` reduces safety, `core` does not, others are unknown.
    fn toolsets(name: &str) -> Option<bool> {
        match name {
            "core" | "network-write" => Some(false),
            "raw" => Some(true),
            _ => None,
        }
    }

    fn admin() -> Role {
        Role::new("admin".to_owned(), Permission::ALL, vec!["*".to_owned()])
    }

    /// Writes `overrides` as the state file at revision 1.
    fn save(state: &StateStore, overrides: McpOverrides) -> TestResult {
        let mut document = McpSettingsDocument::default();
        document.revision = 1;
        document.overrides = overrides;
        state.write(&document)?;
        Ok(())
    }

    /// Todo 23: env > locked kcc.toml key > state > kcc.toml > default, per key.
    #[test]
    fn each_key_takes_the_value_of_its_strongest_source() -> TestResult {
        let mut config = Config::from_toml_str(
            "[mcp]\nlocked = [\"read_only\"]\nread_only = true\nallow_destructive = true\n\
             max_result_bytes = 1000\n",
        )?;
        let reports = config.apply_kcc_env_overrides_with(|var| {
            Ok((var == "KCC_MCP_STDIO_ENABLED").then(|| "true".to_owned()))
        })?;
        let env = EnvOverrides::from_reports(&reports);
        let (_temp, state) = store()?;
        let mut overrides = McpOverrides::default();
        overrides.stdio_enabled = Some(false);
        overrides.read_only = Some(false);
        overrides.max_result_bytes = Some(2000);
        save(&state, overrides)?;

        let resolved = effective(&config, &env, &state)?;

        for (key, source) in [
            (KeyPath::StdioEnabled, Source::Env),
            (KeyPath::ReadOnly, Source::Locked),
            (KeyPath::MaxResultBytes, Source::State),
            (KeyPath::AllowDestructive, Source::Toml),
            (KeyPath::HttpEnabled, Source::Default),
        ] {
            assert_eq!(resolved.source(key), source, "{key}");
        }
        assert!(resolved.settings().stdio_enabled, "env wins over state");
        assert!(resolved.settings().read_only, "a locked key ignores state");
        assert_eq!(
            resolved.settings().max_result_bytes,
            2000,
            "state wins over kcc.toml"
        );
        assert!(
            resolved.settings().allow_destructive,
            "kcc.toml wins over the default"
        );
        assert!(resolved.settings().http_enabled, "the default");
        Ok(())
    }

    /// Todo 23: planning a change writes nothing, and committing it writes the state.
    #[test]
    fn plan_update_writes_nothing_until_commit() -> TestResult {
        let base = McpBase::new(&Config::default(), &EnvOverrides::default());
        let (_temp, state) = store()?;
        let file = state.dir().join(McpSettingsDocument::FILE_NAME);
        let mut change = McpOverrides::default();
        change.max_result_bytes = Some(4096);

        let candidate = base.plan_update(&state, &admin(), &change, &toolsets)?;

        assert!(!file.exists(), "planning wrote the state file");
        assert_eq!(
            candidate.changed(),
            vec![KeyPath::MaxResultBytes],
            "changed keys"
        );
        assert!(
            candidate.restart().is_empty(),
            "a live key restarts nothing"
        );
        commit(&state, &candidate)?;
        let saved = base.effective(&state)?;
        assert_eq!(saved.settings().max_result_bytes, 4096, "committed value");
        assert_eq!(
            saved.source(KeyPath::MaxResultBytes),
            Source::State,
            "source"
        );
        let before = fs::read(&file)?;
        change.max_result_bytes = Some(8192);
        drop(base.plan_update(&state, &admin(), &change, &toolsets)?);
        assert_eq!(fs::read(&file)?, before, "planning rewrote the state file");
        Ok(())
    }

    /// Todo 23: keys set by the environment or locked in kcc.toml cannot be changed.
    #[test]
    fn locked_and_environment_keys_are_refused() -> TestResult {
        let mut config = Config::from_toml_str("[mcp]\nlocked = [\"allow_destructive\"]\n")?;
        let reports = config.apply_kcc_env_overrides_with(|var| {
            Ok((var == "KCC_MCP_READ_ONLY").then(|| "false".to_owned()))
        })?;
        let base = McpBase::new(&config, &EnvOverrides::from_reports(&reports));
        let (_temp, state) = store()?;

        let mut locked = McpOverrides::default();
        locked.allow_destructive = Some(true);
        let refused = base.plan_update(&state, &admin(), &locked, &toolsets);
        assert!(
            matches!(
                refused,
                Err(SettingsError::Locked {
                    key: KeyPath::AllowDestructive
                })
            ),
            "{refused:?}"
        );
        let mut env = McpOverrides::default();
        env.read_only = Some(true);
        let env_refused = base.plan_update(&state, &admin(), &env, &toolsets);
        assert!(
            matches!(
                env_refused,
                Err(SettingsError::EnvSet {
                    key: KeyPath::ReadOnly
                })
            ),
            "{env_refused:?}"
        );
        Ok(())
    }

    /// Todo 23: a toolset the registry does not know is refused.
    #[test]
    fn unknown_toolset_is_refused() -> TestResult {
        let base = McpBase::default();
        let (_temp, state) = store()?;
        let mut change = McpOverrides::default();
        change.toolsets = Some(vec!["core".to_owned(), "shell".to_owned()]);

        let refused = base.plan_update(&state, &admin(), &change, &toolsets);

        assert!(
            matches!(&refused, Err(SettingsError::UnknownToolset { name }) if name == "shell"),
            "{refused:?}"
        );
        Ok(())
    }

    /// Todo 23: a role target above the acting role, or no role at all, is refused, also
    /// when another setting already names that role.
    #[test]
    fn role_targets_above_the_actor_are_refused() -> TestResult {
        let base = McpBase::default();
        let (_temp, state) = store()?;
        let mcp_admin = Role::new(
            "mcp-admin".to_owned(),
            [
                Permission::Read,
                Permission::Write,
                Permission::Save,
                Permission::Migrate,
                Permission::ManageMcp,
            ],
            vec!["*".to_owned()],
        );
        let mut roles = RolesDocument::default();
        roles.roles.push(mcp_admin.clone());
        state.write(&roles)?;

        let mut above = McpOverrides::default();
        above.stdio_role = Some("admin".to_owned());
        let refused = base.plan_update(&state, &mcp_admin, &above, &toolsets);
        assert!(
            matches!(&refused, Err(SettingsError::RoleAbove { name }) if name == "admin"),
            "{refused:?}"
        );
        let mut mapping = McpOverrides::default();
        mapping.auth.oidc.scopes = Some(vec![ScopeMapping::new(
            "kcc".to_owned(),
            "admin".to_owned(),
        )]);
        let mapping_refused = base.plan_update(&state, &mcp_admin, &mapping, &toolsets);
        assert!(
            matches!(&mapping_refused, Err(SettingsError::RoleAbove { name }) if name == "admin"),
            "{mapping_refused:?}"
        );
        let mut missing = McpOverrides::default();
        missing.stdio_role = Some("ghost".to_owned());
        let missing_refused = base.plan_update(&state, &admin(), &missing, &toolsets);
        assert!(
            matches!(&missing_refused, Err(SettingsError::UnknownRole { name }) if name == "ghost"),
            "{missing_refused:?}"
        );
        let mut granted = McpOverrides::default();
        granted.auth.oidc.scopes = Some(vec![ScopeMapping::new(
            "kcc".to_owned(),
            "admin".to_owned(),
        )]);
        commit(
            &state,
            &base.plan_update(&state, &admin(), &granted, &toolsets)?,
        )?;
        let moved_refused = base.plan_update(&state, &mcp_admin, &above, &toolsets);
        assert!(
            matches!(&moved_refused, Err(SettingsError::RoleAbove { name }) if name == "admin"),
            "a role named for another purpose: {moved_refused:?}"
        );
        let mut below = McpOverrides::default();
        below.stdio_role = Some("operator".to_owned());
        drop(base.plan_update(&state, &mcp_admin, &below, &toolsets)?);
        Ok(())
    }

    /// Todo 23: turning destructive tools or `raw` on, or read-only off, is reported as
    /// safety-reducing; a cap change is not.
    #[test]
    fn safety_reducing_changes_are_reported() -> TestResult {
        let config = Config::from_toml_str("[mcp]\nread_only = true\n")?;
        let base = McpBase::new(&config, &EnvOverrides::default());
        let (_temp, state) = store()?;
        let mut change = McpOverrides::default();
        change.allow_destructive = Some(true);
        change.read_only = Some(false);
        change.toolsets = Some(vec!["core".to_owned(), "raw".to_owned()]);
        change.max_result_bytes = Some(1024);

        let candidate = base.plan_update(&state, &admin(), &change, &toolsets)?;

        assert_eq!(
            candidate.safety_reducing(),
            vec![
                KeyPath::ReadOnly,
                KeyPath::AllowDestructive,
                KeyPath::Toolsets
            ],
            "safety-reducing keys"
        );
        let mut tighter = McpOverrides::default();
        tighter.toolsets = Some(vec!["core".to_owned(), "network-write".to_owned()]);
        let tighter_candidate = base.plan_update(&state, &admin(), &tighter, &toolsets)?;
        assert!(
            tighter_candidate.safety_reducing().is_empty(),
            "a safe toolset"
        );
        Ok(())
    }

    /// Todo 23: a non-loopback dedicated listener without a public URL is refused, in
    /// kcc.toml and on the Web.
    #[test]
    fn non_loopback_dedicated_listener_needs_a_public_url() -> TestResult {
        let address = "203.0.113.7";
        let text = format!("[mcp.dedicated]\nenabled = true\nbind = \"{address}\"\n");
        let refused = Config::from_toml_str(&text)?.validate();
        assert!(
            matches!(&refused, Err(ConfigError::Invalid { field, reason: _ }) if field == "mcp.dedicated.public_url"),
            "{refused:?}"
        );
        let with_url = format!("{text}public_url = \"https://mcp.example.net\"\n");
        Config::from_toml_str(&with_url)?.validate()?;

        let (_temp, state) = store()?;
        let mut change = McpOverrides::default();
        change.dedicated.bind = Some(address.parse::<IpAddr>()?);
        let web_refused = McpBase::default().plan_update(&state, &admin(), &change, &toolsets);
        assert!(
            matches!(&web_refused, Err(SettingsError::Invalid(ConfigError::Invalid { field, reason: _ })) if field == "mcp.dedicated.public_url"),
            "{web_refused:?}"
        );
        Ok(())
    }

    /// Todo 23: `mtls = "required"` is refused on the main listener, in kcc.toml and on
    /// the Web; the dedicated listener accepts it.
    #[test]
    fn required_mtls_is_refused_on_the_main_listener() -> TestResult {
        let refused = Config::from_toml_str("[mcp.auth.main]\nmtls = \"required\"\n")?.validate();
        assert!(
            matches!(&refused, Err(ConfigError::Invalid { field, reason: _ }) if field == "mcp.auth.main.mtls"),
            "{refused:?}"
        );
        Config::from_toml_str("[mcp.auth.dedicated]\nmtls = \"required\"\n")?.validate()?;

        let (_temp, state) = store()?;
        let mut change = McpOverrides::default();
        change.auth.main.mtls = Some(MtlsMode::Required);
        let web_refused = McpBase::default().plan_update(&state, &admin(), &change, &toolsets);
        assert!(
            matches!(&web_refused, Err(SettingsError::Invalid(ConfigError::Invalid { field, reason: _ })) if field == "mcp.auth.main.mtls"),
            "{web_refused:?}"
        );
        Ok(())
    }

    /// Todo 23: the state file round-trips, and an unknown field in it is refused.
    #[test]
    fn state_file_round_trips_and_refuses_unknown_fields() -> TestResult {
        let (_temp, state) = store()?;
        let mut overrides = McpOverrides::default();
        overrides.auth.dedicated.mtls = Some(MtlsMode::Optional);
        overrides.toolsets = Some(vec!["core".to_owned()]);
        save(&state, overrides.clone())?;
        let read = state.read::<McpSettingsDocument>()?.ok_or("no document")?;
        assert_eq!(read.overrides, overrides, "round trip");

        let file = state.dir().join(McpSettingsDocument::FILE_NAME);
        let text = fs::read_to_string(&file)?.replacen(
            "\"overrides\": {",
            "\"overrides\": {\n    \"shell_enabled\": true,",
            1,
        );
        fs::write(&file, text)?;
        assert!(
            state.read::<McpSettingsDocument>().is_err(),
            "unknown field accepted"
        );
        assert!(
            McpBase::default().effective(&state).is_err(),
            "the resolver used a document with an unknown field"
        );
        Ok(())
    }

    /// Todo 23: of two changes planned on the same revision, the second save is refused.
    #[test]
    fn commit_after_another_commit_is_refused() -> TestResult {
        let base = McpBase::default();
        let (_temp, state) = store()?;
        let mut first = McpOverrides::default();
        first.max_result_bytes = Some(1024);
        let mut second = McpOverrides::default();
        second.read_only = Some(true);
        let one = base.plan_update(&state, &admin(), &first, &toolsets)?;
        let two = base.plan_update(&state, &admin(), &second, &toolsets)?;

        commit(&state, &one)?;
        let refused = commit(&state, &two);

        assert!(
            matches!(refused, Err(SettingsError::SettingsChanged)),
            "{refused:?}"
        );
        let saved = base.effective(&state)?;
        assert_eq!(
            saved.settings().max_result_bytes,
            1024,
            "the first save stays"
        );
        assert!(
            !saved.settings().read_only,
            "the second save was not written"
        );
        Ok(())
    }

    /// Todo 23: a reset removes the Web value, so kcc.toml applies again.
    #[test]
    fn reset_returns_a_key_to_kcc_toml() -> TestResult {
        let config = Config::from_toml_str("[mcp]\nmax_result_bytes = 1000\n")?;
        let base = McpBase::new(&config, &EnvOverrides::default());
        let (_temp, state) = store()?;
        let mut overrides = McpOverrides::default();
        overrides.max_result_bytes = Some(2000);
        save(&state, overrides)?;

        let candidate = base.reset(&state, &admin(), KeyPath::MaxResultBytes)?;
        assert_eq!(
            base.effective(&state)?.settings().max_result_bytes,
            2000,
            "not yet"
        );
        commit(&state, &candidate)?;

        let resolved = base.effective(&state)?;
        assert_eq!(resolved.settings().max_result_bytes, 1000, "kcc.toml again");
        assert_eq!(
            resolved.source(KeyPath::MaxResultBytes),
            Source::Toml,
            "source"
        );
        Ok(())
    }
}
