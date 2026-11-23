//! The live environment contract of the Entware suites, read through an injected reader so
//! the hermetic tests never touch the process environment.

use std::path::PathBuf;

/// Reads one environment variable; `None` when it is unset.
pub(crate) type Read<'read> = &'read (dyn Fn(&str) -> Option<String> + Sync);

/// Package the SSH suite installs and removes when `KCC_LIVE_ENTWARE_PACKAGE` is unset.
pub(crate) const DEFAULT_PACKAGE: &str = "nano";

/// The router variables every suite needs.
pub(crate) struct Base {
    /// Router origin.
    pub url: String,
    /// Router account.
    pub login: String,
    /// Router password file.
    pub password_file: PathBuf,
    /// Allowed serials.
    pub allowed: Vec<String>,
    /// kcc configuration holding the router's `test_device = true` profile.
    pub config: PathBuf,
}

/// The guided-setup suite's contract.
pub(crate) struct SetupEnv {
    /// Router variables.
    pub base: Base,
    /// The `opkg disk` argument of the spare drive (`<label>:/` or `<uuid>:/`).
    pub drive: String,
}

/// The SSH suite's contract.
pub(crate) struct SshEnv {
    /// Router variables.
    pub base: Base,
    /// File holding the Entware root password.
    pub entware_password_file: PathBuf,
    /// Package installed and removed again.
    pub package: String,
}

/// Reads one non-empty variable or names it in the skip reason.
fn get(read: Read<'_>, name: &str, reason: &'static str) -> Result<String, &'static str> {
    read(name)
        .filter(|value| !value.trim().is_empty())
        .ok_or(reason)
}

/// Requires `name` to be exactly `1`.
fn flag(
    read: Read<'_>,
    name: &str,
    (unset, other): (&'static str, &'static str),
) -> Result<(), &'static str> {
    if get(read, name, unset)?.trim() == "1" {
        Ok(())
    } else {
        Err(other)
    }
}

/// Reads the router variables, or names the first missing one.
pub(crate) fn base(read: Read<'_>) -> Result<Base, &'static str> {
    let url = get(read, "KCC_LIVE_URL", "kcc_live_url-unset")?;
    let login = get(read, "KCC_LIVE_LOGIN", "kcc_live_login-unset")?;
    let password_file = get(
        read,
        "KCC_LIVE_PASSWORD_FILE",
        "kcc_live_password_file-unset",
    )?;
    let allowed = get(read, "KCC_LIVE_ALLOW_SERIAL", "kcc_live_allow_serial-unset")?
        .split(',')
        .map(|serial| serial.trim().to_owned())
        .filter(|serial| !serial.is_empty())
        .collect();
    let config = get(
        read,
        "KCC_LIVE_TARGET_CONFIG",
        "kcc_live_target_config-unset",
    )?;
    Ok(Base {
        url,
        login,
        password_file: PathBuf::from(password_file),
        allowed,
        config: PathBuf::from(config),
    })
}

/// Requires `KCC_LIVE_ALLOW_WRITE=1`.
fn writes_allowed(read: Read<'_>) -> Result<(), &'static str> {
    flag(
        read,
        "KCC_LIVE_ALLOW_WRITE",
        ("kcc_live_allow_write-unset", "kcc_live_allow_write-not-1"),
    )
}

/// Reads the guided-setup contract, or names the first missing or wrong variable.
pub(crate) fn setup(read: Read<'_>) -> Result<SetupEnv, &'static str> {
    let base = base(read)?;
    writes_allowed(read)?;
    flag(
        read,
        "KCC_LIVE_ENTWARE_SETUP",
        (
            "kcc_live_entware_setup-unset",
            "kcc_live_entware_setup-not-1",
        ),
    )?;
    let drive = get(
        read,
        "KCC_LIVE_ENTWARE_DRIVE",
        "kcc_live_entware_drive-unset",
    )?;
    Ok(SetupEnv {
        base,
        drive: drive.trim().to_owned(),
    })
}

/// Reads the SSH contract, or names the first missing or wrong variable.
pub(crate) fn ssh(read: Read<'_>) -> Result<SshEnv, &'static str> {
    let base = base(read)?;
    writes_allowed(read)?;
    let password = get(
        read,
        "KCC_LIVE_ENTWARE_PASSWORD_FILE",
        "kcc_live_entware_password_file-unset",
    )?;
    let package = read("KCC_LIVE_ENTWARE_PACKAGE")
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| DEFAULT_PACKAGE.to_owned());
    Ok(SshEnv {
        base,
        entware_password_file: PathBuf::from(password),
        package,
    })
}

/// Logs `live-skip:<reason>`; the suite then passes, never silently.
pub(crate) fn skip(reason: &str) {
    tracing::warn!("live-skip:{reason}");
}
