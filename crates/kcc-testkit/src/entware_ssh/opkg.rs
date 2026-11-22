//! opkg's fixed answers: the list update and an unknown package. The messages and exit
//! codes are assumed, not captured from a router.

use super::Reply;

/// `opkg update`: the lists downloaded, or (when `fails`) a download error and 255.
pub(super) fn update(fails: bool) -> Reply {
    if fails {
        return Reply {
            stderr: "Collected errors:\n * opkg_download: Failed to download the lists.\n"
                .to_owned(),
            exit: 255,
            ..Reply::default()
        };
    }
    Reply {
        stdout: "Downloading http://bin.entware.net/aarch64-k3.10/Packages.gz\n\
                 Updated list of available packages in /opt/var/opkg-lists/entware\n"
            .to_owned(),
        ..Reply::default()
    }
}

/// opkg's answer for a package it does not know.
pub(super) fn unknown_package(name: &str, collected: &str) -> Reply {
    Reply {
        stderr: format!("Unknown package '{name}'.\nCollected errors:\n * {collected} {name}.\n"),
        exit: 255,
        ..Reply::default()
    }
}
