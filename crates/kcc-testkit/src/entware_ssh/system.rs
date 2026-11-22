//! The Entware userland behind the fake: `opkg` and init scripts following `rc.func`.
//!
//! The init script actions reproduce Entware's `rc.func`
//! (`Entware/rtndev/master/entware-opt/files/rc.func`): `start` returns 8 for a disabled
//! service, 0 when started or already running and 255 when the process did not start;
//! `stop` and `kill` run `check && stop`; `restart` runs `check > /dev/null && stop; start`;
//! `check` prints `alive.` (0) or `dead.` (1); any other action prints the usage line and
//! exits 1. The `opkg` messages and exit codes are assumed, not captured from a router.
//! The enrolment scripts edit `authorized_keys` as their `grep -v` and `printf` would.

use super::{
    Reply, Service, System,
    command::{Command, INIT_D},
    opkg,
};

/// rc.func's `ansi_white`.
const WHITE: &str = "\u{1b}[1;37m";
/// rc.func's `ansi_green`.
const GREEN: &str = "\u{1b}[1;32m";
/// rc.func's `ansi_red`.
const RED: &str = "\u{1b}[1;31m";
/// rc.func's `ansi_yellow`.
const YELLOW: &str = "\u{1b}[1;33m";
/// rc.func's `ansi_std`.
const STD: &str = "\u{1b}[m";
/// The indentation rc.func prints before a result word.
const PAD: &str = "            ";

impl System {
    /// Runs one understood command against the userland.
    pub(super) fn run(&mut self, command: Command) -> Reply {
        match command {
            Command::ListInstalled => {
                let mut out = String::new();
                for (name, version) in &self.installed {
                    put(&mut out, &[name, " - ", version, "\n"]);
                }
                success(out)
            }
            Command::ListUpgradable => {
                let mut out = String::new();
                for (name, new) in &self.upgradable {
                    if let Some(old) = self.installed.get(name) {
                        put(&mut out, &[name, " - ", old, " - ", new, "\n"]);
                    }
                }
                success(out)
            }
            Command::Update => opkg::update(self.update_fails),
            Command::Install(name) => self.install(&name),
            Command::Remove(name) => self.remove(&name),
            Command::Upgrade(name) => self.upgrade(&name),
            Command::ListServices => {
                let mut out = String::new();
                for name in self.services.keys() {
                    put(&mut out, &[name, "\n"]);
                }
                success(out)
            }
            Command::Service { name, action } => self.services.get_mut(&name).map_or_else(
                || not_found(&format!("{INIT_D}{name}")),
                |service| rc_func(&name, service, &action),
            ),
            Command::AppendKey { line, router_id } => {
                let mut kept = without_kcc_line(&self.authorized_keys, &router_id);
                put(&mut kept, &[&line, " kcc:", &router_id, "\n"]);
                self.authorized_keys = kept;
                success(String::new())
            }
            Command::RemoveKey { router_id } => {
                self.authorized_keys = without_kcc_line(&self.authorized_keys, &router_id);
                success(String::new())
            }
            Command::NotFound(word) => not_found(&word),
        }
    }

    /// `opkg install`.
    fn install(&mut self, name: &str) -> Reply {
        if self.frozen.contains(name) {
            return success(String::new());
        }
        if let Some(version) = self.installed.get(name) {
            return success(format!(
                "Package {name} ({version}) installed in root is up to date.\n"
            ));
        }
        let Some(version) = self.installable.remove(name) else {
            return opkg::unknown_package(name, "opkg_install_cmd: Cannot install package");
        };
        let reply = success(format!(
            "Installing {name} ({version}) to root...\nConfiguring {name}.\n"
        ));
        drop(self.installed.insert(name.to_owned(), version));
        reply
    }

    /// `opkg remove`; the package goes back to the feed.
    fn remove(&mut self, name: &str) -> Reply {
        if self.frozen.contains(name) {
            return success(String::new());
        }
        let Some(version) = self.installed.remove(name) else {
            return success("No packages removed.\n".to_owned());
        };
        drop(self.upgradable.remove(name));
        drop(self.installable.insert(name.to_owned(), version));
        success(format!("Removing package {name} from root...\n"))
    }

    /// `opkg upgrade`.
    fn upgrade(&mut self, name: &str) -> Reply {
        if self.frozen.contains(name) {
            return success(String::new());
        }
        let Some(old) = self.installed.get(name).cloned() else {
            return opkg::unknown_package(name, "opkg_upgrade_cmd: Cannot upgrade package");
        };
        let Some(new) = self.upgradable.remove(name) else {
            return success(String::new());
        };
        let reply = success(format!(
            "Upgrading {name} on root from {old} to {new}...\nConfiguring {name}.\n"
        ));
        drop(self.installed.insert(name.to_owned(), new));
        reply
    }
}

/// `grep -v ' kcc:<router_id>$'` of `text`: every other line, each ending in a newline.
fn without_kcc_line(text: &str, router_id: &str) -> String {
    let marker = format!(" kcc:{router_id}");
    let mut kept = String::new();
    for line in text.split_terminator('\n') {
        if !line.ends_with(&marker) {
            put(&mut kept, &[line, "\n"]);
        }
    }
    kept
}

/// Exit 0 with `stdout`.
fn success(stdout: String) -> Reply {
    Reply {
        stdout,
        ..Reply::default()
    }
}

/// The shell's answer for a program it cannot find.
fn not_found(word: &str) -> Reply {
    Reply {
        stderr: format!("sh: {word}: not found\n"),
        exit: 127,
        ..Reply::default()
    }
}

/// Runs `/opt/etc/init.d/<name> <action>` as rc.func does.
fn rc_func(name: &str, service: &mut Service, action: &str) -> Reply {
    let mut out = String::new();
    let exit = match action {
        "start" => {
            let code = start(service, &mut out);
            forced(service, code)
        }
        "stop" | "kill" => {
            let code = match check(service, &mut out) {
                0 => stop(service, action, &mut out),
                dead => dead,
            };
            forced(service, code)
        }
        "restart" => {
            if check(service, &mut String::new()) == 0 {
                let _: u32 = stop(service, action, &mut out);
            }
            let code = start(service, &mut out);
            forced(service, code)
        }
        "check" => check(service, &mut out),
        "reconfigure" => {
            put(
                &mut out,
                &[
                    WHITE,
                    " Sending SIGHUP to ",
                    &service.process,
                    "... ",
                    STD,
                    "\n",
                ],
            );
            u32::from(!service.running)
        }
        _ => {
            put(
                &mut out,
                &[
                    WHITE,
                    " Usage: ",
                    INIT_D,
                    name,
                    " (start|stop|restart|check|kill|reconfigure)",
                    STD,
                    "\n",
                ],
            );
            1
        }
    };
    Reply {
        stdout: out,
        exit,
        ..Reply::default()
    }
}

/// `code`, or the status the service is configured to report instead.
const fn forced(service: &Service, code: u32) -> u32 {
    match service.exit {
        Some(forced) => forced,
        None => code,
    }
}

/// rc.func's `start`.
fn start(service: &mut Service, out: &mut String) -> u32 {
    if !service.enabled {
        return 8;
    }
    put(out, &[WHITE, " Starting ", &service.process, "... ", STD]);
    if service.running {
        put(out, &[PAD, YELLOW, " already running. ", STD, "\n"]);
        return 0;
    }
    if service.failing {
        put(out, &[PAD, RED, " failed. ", STD, "\n"]);
        return 255;
    }
    service.running = true;
    put(out, &[PAD, GREEN, " done. ", STD, "\n"]);
    0
}

/// rc.func's `stop` for `stop`, `restart` and `kill`.
fn stop(service: &mut Service, action: &str, out: &mut String) -> u32 {
    let verb = if action == "kill" {
        " Killing "
    } else {
        " Shutting down "
    };
    put(out, &[WHITE, verb, &service.process, "... ", STD]);
    if !service.failing {
        service.running = false;
    }
    if service.running {
        put(out, &[PAD, RED, " failed. ", STD, "\n"]);
        return 255;
    }
    put(out, &[PAD, GREEN, " done. ", STD, "\n"]);
    0
}

/// rc.func's `check`.
fn check(service: &Service, out: &mut String) -> u32 {
    put(out, &[WHITE, " Checking ", &service.process, "... "]);
    if service.running {
        put(out, &[PAD, GREEN, " alive. ", STD, "\n"]);
        0
    } else {
        put(out, &[PAD, RED, " dead. ", STD, "\n"]);
        1
    }
}

/// Appends `parts` to `out`.
fn put(out: &mut String, parts: &[&str]) {
    for part in parts {
        out.push_str(part);
    }
}
