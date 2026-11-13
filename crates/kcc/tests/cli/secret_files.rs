//! Secret input files that group or others can read are refused (unix).

use std::{fs, os::unix::fs::PermissionsExt as _};

use fluent_bundle::FluentArgs;
use kcc_i18n::{bundle::tr, keys, locale::Locale};

use super::support::{Env, TestResult};

/// A `--password-file` other users can read exits 3 with the chmod hint naming it.
#[test]
fn secret_file_readable_by_others_exits_auth_with_chmod_hint() -> TestResult {
    let env = Env::new("")?;
    let password = env.write("alice.password", &"alice-".repeat(3))?;
    fs::set_permissions(&password, fs::Permissions::from_mode(0o644))?;
    let shown = password.to_str().ok_or("non-UTF-8 path")?;

    let added = env.kcc(&["--password-file", shown, "user", "add", "alice"])?;

    let mut args = FluentArgs::new();
    args.set("path", shown);
    assert_eq!(added.code, 3_i32, "{added:?}");
    assert!(
        added.stderr.contains(&tr(
            Locale::En,
            keys::ERRORS_SECRET_FILE_PERMISSIONS,
            Some(&args)
        )),
        "{added:?}"
    );
    Ok(())
}
