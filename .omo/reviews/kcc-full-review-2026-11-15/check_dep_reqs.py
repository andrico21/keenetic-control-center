#!/usr/bin/env python3
"""Check that every crates.io version requirement equals the version locked for it.

usage: python3 check_dep_reqs.py        (run from the repository root)

Covers the root workspace and the separate `xtask/` workspace. For each workspace member
and each crates.io dependency it declares (normal, dev, build, target-specific), the
requirement written in the manifest (`^` stripped) must equal the version in the lockfile,
which is what `cargo add` writes for the latest version past the cooldown. `--all-features`
makes optional dependencies count too. Exit 0 only when every requirement matches.
`--locked` makes cargo fail instead of rewriting a stale lockfile.
"""
import json
import subprocess
import sys

bad = []
for manifest in ("Cargo.toml", "xtask/Cargo.toml"):
    md = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--locked", "--all-features",
         "--manifest-path", manifest]))
    pkgs = {p["id"]: p for p in md["packages"]}
    nodes = {n["id"]: n for n in md["resolve"]["nodes"]}
    for member in md["workspace_members"]:
        locked = {pkgs[d["pkg"]]["name"]: pkgs[d["pkg"]]["version"].split("+")[0]
                  for d in nodes[member]["deps"]}
        for dep in pkgs[member]["dependencies"]:
            src = dep["source"] or ""
            if "crates.io" in src and dep["name"] in locked and dep["req"].lstrip("^") != locked[dep["name"]]:
                bad.append(f"{manifest}: {pkgs[member]['name']} -> {dep['name']} "
                           f"requirement {dep['req']}, locked {locked[dep['name']]}")
print("\n".join(sorted(set(bad))) or "every requirement equals its locked version")
sys.exit(1 if bad else 0)
