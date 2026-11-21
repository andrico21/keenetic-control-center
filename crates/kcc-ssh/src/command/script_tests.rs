//! The rendered `authorized_keys` scripts executed by `/bin/sh` in a temp directory.
//!
//! Each case renders a script with dropbear's directory moved into a temp root and a
//! hermetic `PATH` of temp directories holding symlinks to the host's tools (found only
//! at `/usr/bin/<tool>` or `/bin/<tool>`, never through the host `PATH`): `tools` holds
//! `mkdir`, `touch`, `mv`, `chmod` and `rm`; `grep` holds the real `grep`; `stub` holds a
//! `grep` that exits 2.

use core::error::Error;
use std::{
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

use super::EntwareCommand;
use crate::{
    grammar::{PublicKeyLine, RouterId},
    keys::generate_ed25519,
};

/// Result of a script test.
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// A temp root with dropbear's directory and the three tool directories.
struct Sandbox {
    /// Owns the temp root.
    _root: TempDir,
    /// The temp root.
    root: PathBuf,
}

impl Sandbox {
    /// Creates the root (refusing a path a shell would split or expand) and the tool
    /// directories.
    fn new() -> TestResult<Self> {
        let dir = tempfile::Builder::new().prefix("kcc-ssh-").tempdir()?;
        let root = dir.path().to_path_buf();
        let text = root.to_str().ok_or("temp path is not UTF-8")?;
        assert!(
            text.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte)),
            "the temp path {text:?} holds whitespace or shell metacharacters; set TMPDIR to a plain path"
        );
        for tool in ["mkdir", "touch", "mv", "chmod", "rm"] {
            link(&root.join("tools"), tool)?;
        }
        link(&root.join("grep"), "grep")?;
        let stub = root.join("stub");
        fs::create_dir_all(&stub)?;
        fs::write(stub.join("grep"), "#!/bin/sh\nexit 2\n")?;
        fs::set_permissions(stub.join("grep"), fs::Permissions::from_mode(0o755))?;
        Ok(Self { _root: dir, root })
    }

    /// dropbear's directory inside the root.
    fn dropbear(&self) -> PathBuf {
        self.root.join("opt/etc/dropbear")
    }

    /// The `authorized_keys` file.
    fn keys(&self) -> PathBuf {
        self.dropbear().join("authorized_keys")
    }

    /// The temp file the scripts write first.
    fn temp_file(&self) -> PathBuf {
        self.dropbear().join("authorized_keys.kcc")
    }

    /// A `PATH` value of the named tool directories.
    fn path(&self, dirs: &[&str]) -> String {
        dirs.iter()
            .map(|dir| self.root.join(dir).display().to_string())
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Writes `text` as an existing `authorized_keys`.
    fn existing(&self, text: &str) -> TestResult {
        fs::create_dir_all(self.dropbear())?;
        fs::write(self.keys(), text)?;
        Ok(())
    }

    /// Renders `command` for this root and `PATH` from `dirs` and runs it.
    fn run(&self, command: &EntwareCommand, dirs: &[&str]) -> TestResult<Output> {
        let dir = self.dropbear();
        let dropbear = dir.to_str().ok_or("temp path is not UTF-8")?;
        shell(&command.render_with(dropbear, &self.path(dirs)))
    }
}

/// Links the host's `tool` into `dir`, found at `/usr/bin/<tool>` or `/bin/<tool>`.
fn link(dir: &Path, tool: &str) -> TestResult {
    let host = [Path::new("/usr/bin"), Path::new("/bin")]
        .into_iter()
        .map(|bin| bin.join(tool))
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| format!("no /usr/bin/{tool} or /bin/{tool} on this host"))?;
    fs::create_dir_all(dir)?;
    symlink(host, dir.join(tool))?;
    Ok(())
}

/// Runs `script` with `/bin/sh -c` in an empty environment; returns its exit status and
/// output.
#[expect(
    clippy::disallowed_methods,
    reason = "test executes the rendered script under a real shell"
)]
fn shell(script: &str) -> TestResult<Output> {
    Ok(Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .env_clear()
        .output()?)
}

/// A generated public key line and the router `home-1`.
fn key_and_router() -> TestResult<(PublicKeyLine, RouterId)> {
    let (_private, line) = generate_ed25519()?;
    Ok((PublicKeyLine::parse(&line)?, RouterId::parse("home-1")?))
}

/// The `AppendKey` command and the line it installs.
fn append() -> TestResult<(EntwareCommand, String)> {
    let (line, router_id) = key_and_router()?;
    let entry = format!("{} kcc:{}\n", line.as_str(), router_id.as_str());
    Ok((EntwareCommand::AppendKey { line, router_id }, entry))
}

/// The `RemoveKey` command for `home-1`.
fn remove() -> TestResult<EntwareCommand> {
    Ok(EntwareCommand::RemoveKey {
        router_id: RouterId::parse("home-1")?,
    })
}

/// Two keys that are not kcc's line for `home-1`: an admin key and another router's line
/// whose id starts with `home-1`.
fn other_keys() -> TestResult<String> {
    let (_first, admin) = generate_ed25519()?;
    let (_second, other) = generate_ed25519()?;
    Ok(format!("{admin} admin@laptop\n{other} kcc:home-10\n"))
}

/// The permission bits of `path`.
fn mode(path: &Path) -> TestResult<u32> {
    Ok(fs::metadata(path)?.permissions().mode() & 0o777)
}

/// Todo 7: a missing file and directory are created; the file holds kcc's line only,
/// mode 600, in a directory of mode 700.
#[test]
fn append_creates_missing_file() -> TestResult {
    let sandbox = Sandbox::new()?;
    let (command, entry) = append()?;
    assert!(
        sandbox.run(&command, &["grep", "tools"])?.status.success(),
        "script exit"
    );
    assert_eq!(fs::read_to_string(sandbox.keys())?, entry);
    assert_eq!(mode(&sandbox.keys())?, 0o600, "file mode");
    assert_eq!(mode(&sandbox.dropbear())?, 0o700, "directory mode");
    assert!(!sandbox.temp_file().exists(), "no temp file left");
    Ok(())
}

/// Todo 7: an older kcc line of the same router is replaced; the file keeps one line.
#[test]
fn append_replaces_the_kcc_line() -> TestResult {
    let sandbox = Sandbox::new()?;
    let (old, _old_entry) = append()?;
    let (command, entry) = append()?;
    assert!(
        sandbox.run(&old, &["grep", "tools"])?.status.success(),
        "first run"
    );
    assert!(
        sandbox.run(&command, &["grep", "tools"])?.status.success(),
        "second run"
    );
    assert_eq!(fs::read_to_string(sandbox.keys())?, entry);
    Ok(())
}

/// Todo 7: other keys are kept byte for byte, kcc's line is added after them, and a
/// second run leaves the file identical.
#[test]
fn append_keeps_other_keys_and_is_idempotent() -> TestResult {
    let sandbox = Sandbox::new()?;
    let others = other_keys()?;
    sandbox.existing(&others)?;
    let (command, entry) = append()?;
    assert!(
        sandbox.run(&command, &["grep", "tools"])?.status.success(),
        "first run"
    );
    let first = fs::read_to_string(sandbox.keys())?;
    assert_eq!(first, format!("{others}{entry}"));
    assert!(
        sandbox.run(&command, &["grep", "tools"])?.status.success(),
        "rerun"
    );
    assert_eq!(
        fs::read_to_string(sandbox.keys())?,
        first,
        "rerun is identical"
    );
    assert_eq!(mode(&sandbox.keys())?, 0o600, "file mode");
    Ok(())
}

/// Todo 7: `RemoveKey` drops only kcc's line; a missing file becomes an empty one.
#[test]
fn remove_keeps_other_keys() -> TestResult {
    let sandbox = Sandbox::new()?;
    let others = other_keys()?;
    sandbox.existing(&others)?;
    let (command, _entry) = append()?;
    assert!(
        sandbox.run(&command, &["grep", "tools"])?.status.success(),
        "append"
    );
    assert!(
        sandbox
            .run(&remove()?, &["grep", "tools"])?
            .status
            .success(),
        "remove"
    );
    assert_eq!(fs::read_to_string(sandbox.keys())?, others);
    let empty = Sandbox::new()?;
    fs::create_dir_all(empty.dropbear())?;
    assert!(
        empty.run(&remove()?, &["grep", "tools"])?.status.success(),
        "remove from nothing"
    );
    assert_eq!(fs::read_to_string(empty.keys())?, "");
    assert!(
        !sandbox.temp_file().exists() && !empty.temp_file().exists(),
        "no temp file"
    );
    Ok(())
}

/// Todo 7: when `grep` fails (exit 2) or is missing (127), both scripts fail, the file
/// is byte-identical and no temp file is left.
#[test]
fn grep_failure_leaves_the_file_untouched() -> TestResult {
    for dirs in [&["stub", "tools"][..], &["tools"][..]] {
        let sandbox = Sandbox::new()?;
        let before = other_keys()?;
        sandbox.existing(&before)?;
        let (command, _entry) = append()?;
        for script in [command, remove()?] {
            let output = sandbox.run(&script, dirs)?;
            assert!(!output.status.success(), "{dirs:?} {script:?} {output:?}");
            assert_eq!(
                fs::read_to_string(sandbox.keys())?,
                before,
                "{dirs:?} {script:?}"
            );
            assert!(
                !sandbox.temp_file().exists(),
                "{dirs:?} {script:?} left a temp file"
            );
        }
    }
    Ok(())
}
