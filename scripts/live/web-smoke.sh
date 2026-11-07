#!/usr/bin/env bash
# Web UI smoke through a real browser: kcc serve pointed at one router, Playwright logs in,
# opens the dashboard and the clients page, sets an interface description, reads it back
# from a fresh page load, restores the original and reads that back, with screenshots.
#
#   scripts/live/web-smoke.sh --fake   hermetic: a kcc-testkit fake router (KN-1811 5.1)
#   scripts/live/web-smoke.sh          live: the router of the KCC_LIVE_* contract
#
# Live mode needs KCC_LIVE_URL, KCC_LIVE_LOGIN, KCC_LIVE_PASSWORD_FILE, KCC_LIVE_ALLOW_SERIAL,
# KCC_LIVE_ALLOW_WRITE=1 and KCC_LIVE_TARGET_CONFIG (its [[routers]] entry for KCC_LIVE_URL
# has test_device = true). A missing variable prints `live-skip:<reason>` and exits 0. The
# serial from `show identification` is checked before kcc serve starts; the write runs under
# the router fail-safe timer (900 s), which is disarmed only after the original description
# is read back. Nothing is saved.
#
# Environment: CARGO_TARGET_DIR (kcc and kcc-fake-router binaries), KCC_WEB_PORT (default
# 18451), KCC_WEB_FAKE_PORT (default 18452), KCC_WEB_INTERFACE (default Bridge0),
# KCC_PLAYWRIGHT_IMAGE (default mcr.microsoft.com/playwright:v1.64.1-noble),
# KCC_PLAYWRIGHT_MODULES (a node_modules holding playwright 1.64.1), KCC_EVIDENCE_DIR
# (default .omo/evidence), KCC_WEB_KEEP=1 (keep the work directory).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="${ROOT}/scripts/live"
MODE=live
[[ "${1:-}" == --fake ]] && MODE=fake
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
PORT="${KCC_WEB_PORT:-18451}"
FAKE_PORT="${KCC_WEB_FAKE_PORT:-18452}"
INTERFACE="${KCC_WEB_INTERFACE:-Bridge0}"
IMAGE="${KCC_PLAYWRIGHT_IMAGE:-mcr.microsoft.com/playwright:v1.64.1-noble}"
MODULES="${KCC_PLAYWRIGHT_MODULES:-}"
EVIDENCE="${KCC_EVIDENCE_DIR:-${ROOT}/.omo/evidence}"
PREFIX="task-51-keenetic-control-center-${MODE}"

skip() {
  echo "live-skip:$1"
  exit 0
}

if [[ "${MODE}" == live ]]; then
  [[ -n "${KCC_LIVE_URL:-}" ]] || skip "kcc_live_url-unset"
  [[ -n "${KCC_LIVE_LOGIN:-}" ]] || skip "kcc_live_login-unset"
  [[ -n "${KCC_LIVE_PASSWORD_FILE:-}" ]] || skip "kcc_live_password_file-unset"
  [[ -n "${KCC_LIVE_ALLOW_SERIAL:-}" ]] || skip "kcc_live_allow_serial-unset"
  [[ "${KCC_LIVE_ALLOW_WRITE:-}" == 1 ]] || skip "kcc_live_allow_write-not-1"
  [[ -n "${KCC_LIVE_TARGET_CONFIG:-}" ]] || skip "kcc_live_target_config-unset"
fi
[[ -n "${MODULES}" && -d "${MODULES}/playwright" ]] \
  || { echo "set KCC_PLAYWRIGHT_MODULES to a node_modules holding playwright 1.64.1" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kcc51-web.XXXXXX")"
PIDS=()
cleanup() {
  local pid
  for pid in "${PIDS[@]}"; do kill -INT "${pid}" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "${pid}" 2>/dev/null || true; done
  if [[ "${KCC_WEB_KEEP:-0}" == 1 ]]; then echo "kept ${WORK}"; else rm -rf "${WORK}"; fi
}
trap cleanup EXIT

# Waits up to $1 seconds for a line matching $3 in file $2.
wait_line() {
  local tries=$(($1 * 4))
  while ((tries > 0)); do
    grep -q -- "$3" "$2" 2>/dev/null && return 0
    sleep 0.25
    tries=$((tries - 1))
  done
  echo "timed out waiting for '$3' in $2" >&2
  tail -n 20 "$2" >&2
  return 1
}

mkdir -p "${WORK}/home/config" "${WORK}/home/state" "${EVIDENCE}"
head -c 32 /dev/urandom >"${WORK}/master.key"
chmod 0600 "${WORK}/master.key"

if [[ "${MODE}" == fake ]]; then
  head -c 18 /dev/urandom | base64 | tr -d '\n/+=' >"${WORK}/router.password"
  chmod 0600 "${WORK}/router.password"
  "${TARGET_DIR}/debug/kcc-fake-router" --model KN-1811 --firmware 5.1 \
    --bind "127.0.0.1:${FAKE_PORT}" --password-file "${WORK}/router.password" \
    >"${WORK}/router.log" 2>&1 &
  PIDS+=("$!")
  wait_line 30 "${WORK}/router.log" "fake router listening"
  ROUTER_URL="http://127.0.0.1:${FAKE_PORT}"
  ROUTER_LOGIN="admin"
  ROUTER_PASSWORD_FILE="${WORK}/router.password"
  ALLOW_LOOPBACK=true
else
  ROUTER_URL="${KCC_LIVE_URL%/}"
  ROUTER_LOGIN="${KCC_LIVE_LOGIN}"
  ROUTER_PASSWORD_FILE="$(realpath "${KCC_LIVE_PASSWORD_FILE}")"
  ALLOW_LOOPBACK=false
  # The profile gate runs before any router contact.
  python3 - "${KCC_LIVE_TARGET_CONFIG}" "${ROUTER_URL}" <<'EOF'
import sys, tomllib
config = tomllib.load(open(sys.argv[1], "rb"))
wanted = sys.argv[2].rstrip("/")
for router in config.get("routers", []):
    if router.get("url", "").rstrip("/") == wanted:
        sys.exit(0 if router.get("test_device") is True else "refused: profile is not test_device = true")
sys.exit("refused: no router profile for KCC_LIVE_URL")
EOF
fi

cat >"${WORK}/kcc.toml" <<EOF
[server]
listen_addr = "127.0.0.1"
listen_port = ${PORT}
allowed_origins = ["http://127.0.0.1:${PORT}"]

[web]
enabled = true

[mcp]
http_enabled = false

[outbound]
allow_loopback = ${ALLOW_LOOPBACK}

[state]
dir = "${WORK}/state"

[[routers]]
name = "lab"
url = "${ROUTER_URL}"
login = "${ROUTER_LOGIN}"
password_file = "${ROUTER_PASSWORD_FILE}"
test_device = true
EOF
# kcc runs with a hermetic home; podman keeps the invoking user's own.
KCC=(env HOME="${WORK}/home" XDG_CONFIG_HOME="${WORK}/home/config"
  XDG_STATE_HOME="${WORK}/home/state" KCC_MASTER_KEY_FILE="${WORK}/master.key"
  "${TARGET_DIR}/debug/kcc" --config "${WORK}/kcc.toml")

RCI=(python3 "${HERE}/rci.py" "${ROUTER_URL}" "${ROUTER_LOGIN}" "${ROUTER_PASSWORD_FILE}")

# Serial allowlist: one read before anything else touches the router.
SERIAL="$("${RCI[@]}" serial)"
if [[ "${MODE}" == live ]]; then
  ALLOWED=",${KCC_LIVE_ALLOW_SERIAL// /},"
  [[ -n "${SERIAL}" && "${ALLOWED}" == *",${SERIAL},"* ]] \
    || { echo "refused: router serial is not in KCC_LIVE_ALLOW_SERIAL" >&2; exit 1; }
fi
echo "router serial allowlisted (sha256 $(printf '%s' "${SERIAL}" | sha256sum | cut -c1-16))"

head -c 18 /dev/urandom | base64 | tr -d '\n/+=' >"${WORK}/web.password"
"${KCC[@]}" --password-file "${WORK}/web.password" user add smoke --role admin >/dev/null

"${KCC[@]}" serve >"${WORK}/serve.log" 2>&1 &
PIDS+=("$!")
wait_line 60 "${WORK}/serve.log" "kcc listening"

"${RCI[@]}" parse "system configuration fail-safe timer reboot 900"
podman run --rm --network host --ipc host \
  -v "${HERE}:/qa:ro" -v "${MODULES}:/qa/node_modules:ro" -v "${EVIDENCE}:/evidence" \
  -e "BASE=http://127.0.0.1:${PORT}" -e "ROUTER=lab" -e "INTERFACE=${INTERFACE}" \
  -e "WEB_USER=smoke" -e "WEB_PASSWORD=$(cat "${WORK}/web.password")" \
  -e "OUT=/evidence/${PREFIX}" -w /qa "${IMAGE}" node web-smoke.mjs
"${RCI[@]}" parse "no system configuration fail-safe timer"
"${KCC[@]}" --router lab --json config state | jq -c '{unsaved, fail_safe: ."fail-safe"}'
echo "web smoke (${MODE}): pass"
