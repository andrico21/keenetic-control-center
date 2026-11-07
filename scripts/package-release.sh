#!/usr/bin/env bash
# Packages one kcc release binary, or verifies a directory of packaged archives.
#
#   scripts/package-release.sh <version> <target> <binary-path> <out-dir>
#       Writes <out-dir>/kcc-<version>-<target>.tar.gz (.zip for Windows
#       targets) holding the binary, LICENSE-APACHE, LICENSE-MIT, README.md
#       and kcc.example.toml under a kcc-<version>-<target>/ directory, and
#       appends its checksum line to <out-dir>/SHA256SUMS.
#   scripts/package-release.sh --verify <dir>
#       Checks every line of <dir>/SHA256SUMS; exits non-zero on any mismatch.
#
# Used by .github/workflows/release.yml and locally (Linux, macOS, Git Bash).
set -euo pipefail

usage() {
    printf 'usage: %s <version> <target> <binary-path> <out-dir>\n' "$0" >&2
    printf '       %s --verify <dir>\n' "$0" >&2
    exit 2
}

die() {
    printf 'package-release: %s\n' "$*" >&2
    exit 1
}

# sha256 [-c] <args>: GNU sha256sum, else the macOS shasum equivalent.
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$@"
    else
        shasum -a 256 "$@"
    fi
}

verify() {
    local dir=$1
    [[ -f "$dir/SHA256SUMS" ]] || die "no SHA256SUMS in $dir"
    (cd "$dir" && sha256 -c SHA256SUMS)
}

package() {
    local version=$1 target=$2 binary=$3 out_dir=$4
    [[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]] || die "invalid version: $version"
    [[ "$target" =~ ^[a-z0-9_]+(-[a-z0-9_]+)+$ ]] || die "invalid target: $target"
    [[ -f "$binary" ]] || die "binary not found: $binary"

    local root
    root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
    local name="kcc-$version-$target"
    local archive
    case "$target" in
        *-windows-*) archive="$name.zip" ;;
        *) archive="$name.tar.gz" ;;
    esac

    mkdir -p "$out_dir"
    out_dir=$(cd "$out_dir" && pwd)
    stage=$(mktemp -d)
    trap 'rm -rf "$stage"' EXIT

    mkdir "$stage/$name"
    cp "$binary" "$stage/$name/"
    for file in LICENSE-APACHE LICENSE-MIT README.md kcc.example.toml; do
        cp "$root/$file" "$stage/$name/"
    done

    rm -f "$out_dir/$archive"
    case "$archive" in
        *.zip)
            if command -v zip >/dev/null 2>&1; then
                (cd "$stage" && zip -qr "$out_dir/$archive" "$name")
            else
                (cd "$stage" && 7z a -tzip -bd "$out_dir/$archive" "$name" >/dev/null)
            fi
            ;;
        *) tar -czf "$out_dir/$archive" -C "$stage" "$name" ;;
    esac

    local sums="$out_dir/SHA256SUMS"
    if [[ -f "$sums" ]]; then
        # Re-packaging the same archive replaces its line instead of duplicating it.
        awk -v f="$archive" '$2 != f && $2 != "*" f' "$sums" >"$sums.tmp"
        mv "$sums.tmp" "$sums"
    fi
    (cd "$out_dir" && sha256 "$archive") >>"$sums"
    printf '%s\n' "$out_dir/$archive"
}

case "${1:-}" in
    --verify)
        [[ $# -eq 2 ]] || usage
        verify "$2"
        ;;
    -h | --help | "") usage ;;
    *)
        [[ $# -eq 4 ]] || usage
        package "$@"
        ;;
esac
