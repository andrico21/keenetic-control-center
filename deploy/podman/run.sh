#!/usr/bin/env bash
# Runs kcc with the same hardening as deploy/podman/kcc.container, for hosts without
# Quadlet. Prerequisites (secrets, config directory, seccomp profile) are in
# deploy/podman/README.md.
#
#   deploy/podman/run.sh [image]          (default ghcr.io/andrico21/keenetic-control-center:latest)
#
# Environment: KCC_CONFIG_DIR (default ~/.config/kcc/etc), KCC_SECCOMP (default
# deploy/podman/seccomp-kcc.json next to this script), KCC_PUBLISH_METRICS=1 to publish
# the metrics listener on host loopback, KCC_ROUTER_SECRETS (space-separated Podman
# secret names mounted under /run/secrets, default "kcc-router-home").
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="${1:-ghcr.io/andrico21/keenetic-control-center:latest}"
CONFIG_DIR="${KCC_CONFIG_DIR:-${HOME}/.config/kcc/etc}"
SECCOMP="${KCC_SECCOMP:-${HERE}/seccomp-kcc.json}"

if [[ "$(podman info --format '{{.Host.Security.Rootless}}')" != true ]]; then
  echo "run.sh: rootless Podman required; run it as your own user, not root" >&2
  exit 1
fi

secret() {
  printf '%s,target=/run/secrets/%s,uid=65532,gid=65532,mode=0400' "$1" "$1"
}

args=(
  --name kcc
  --detach
  --replace
  --user 65532:65532
  --read-only
  --cap-drop=ALL
  --security-opt no-new-privileges
  --security-opt "seccomp=${SECCOMP}"
  --memory=256m --memory-swap=256m --pids-limit=128
  --stop-timeout 100
  --secret "$(secret kcc-master-key)"
  --secret "$(secret kcc-tls-cert)"
  --secret "$(secret kcc-tls-key)"
  -v "kcc-state:/var/lib/kcc:U,Z"
  -v "${CONFIG_DIR}:/etc/kcc:ro,Z"
  -p 127.0.0.1:8443:8443
  --health-cmd '["/kcc","healthcheck","--config","/etc/kcc/kcc.toml"]'
  --health-interval 30s --health-timeout 10s --health-start-period 20s --health-retries 3
)
for name in ${KCC_ROUTER_SECRETS:-kcc-router-home}; do
  args+=(--secret "$(secret "${name}")")
done
if [[ "${KCC_PUBLISH_METRICS:-0}" == 1 ]]; then
  args+=(-p 127.0.0.1:9090:9090)
fi

exec podman run "${args[@]}" "${IMAGE}"
