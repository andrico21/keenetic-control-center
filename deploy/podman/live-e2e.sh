#!/usr/bin/env bash
# Live container path: the hardened image (`kcc:test`) in rootless Podman under the
# shipped seccomp profile, pointed at the owner's live test router. Steps: Web login and
# dashboard, one reversible write (a `02:` known host registered, read back and removed),
# a /metrics scrape showing the router's series, log forwarding to the kcc-testkit fake
# Loki, one `kcc copy --from file:<KCC_LIVE_SOURCE_FILE> --to lab --groups dns-secure
# --finish rollback`, and zero seccomp denials in every log.
#
#   deploy/podman/live-e2e.sh [--image <ref>] [--seccomp <profile.json>]
#
# Needs KCC_LIVE_URL, KCC_LIVE_LOGIN, KCC_LIVE_PASSWORD_FILE, KCC_LIVE_ALLOW_SERIAL,
# KCC_LIVE_ALLOW_WRITE=1, KCC_LIVE_TARGET_CONFIG (its [[routers]] entry for KCC_LIVE_URL has
# test_device = true), KCC_LIVE_SOURCE_FILE, and KCC_LIVE_ALLOW_REBOOT=1 (the fail-safe
# rollback of the copy reboots the router into its startup configuration). A missing
# variable prints `live-skip:<reason>` and exits 0. The serial is checked on the host before
# the container starts. Same structure as deploy/podman/e2e.sh (its step/wait_line helpers
# are copied, not sourced: e2e.sh runs its whole drive when sourced).
#
# Environment: CARGO_TARGET_DIR (kcc-fake-sinks), KCC_LIVE_E2E_NAME (podman object prefix,
# default kcc51-live), KCC_LIVE_E2E_WEB_PORT (default 18543), KCC_LIVE_E2E_METRICS_PORT
# (default 19590), KCC_LIVE_E2E_KEEP=1 (keep the work directory).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="kcc:test"
SECCOMP="${ROOT}/deploy/podman/seccomp-kcc.json"
while (($# > 0)); do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --seccomp) SECCOMP="$(realpath "$2")"; shift 2 ;;
    *) echo "usage: $0 [--image <ref>] [--seccomp <json>]" >&2; exit 2 ;;
  esac
done

skip() {
  echo "live-skip:$1"
  exit 0
}
[[ -n "${KCC_LIVE_URL:-}" ]] || skip "kcc_live_url-unset"
[[ -n "${KCC_LIVE_LOGIN:-}" ]] || skip "kcc_live_login-unset"
[[ -n "${KCC_LIVE_PASSWORD_FILE:-}" ]] || skip "kcc_live_password_file-unset"
[[ -n "${KCC_LIVE_ALLOW_SERIAL:-}" ]] || skip "kcc_live_allow_serial-unset"
[[ "${KCC_LIVE_ALLOW_WRITE:-}" == 1 ]] || skip "kcc_live_allow_write-not-1"
[[ -n "${KCC_LIVE_TARGET_CONFIG:-}" ]] || skip "kcc_live_target_config-unset"
[[ -n "${KCC_LIVE_SOURCE_FILE:-}" ]] || skip "kcc_live_source_file-unset"
[[ "${KCC_LIVE_ALLOW_REBOOT:-}" == 1 ]] || skip "kcc_live_allow_reboot-not-1"

NAME="${KCC_LIVE_E2E_NAME:-kcc51-live}"
WEB_PORT="${KCC_LIVE_E2E_WEB_PORT:-18543}"
METRICS_PORT="${KCC_LIVE_E2E_METRICS_PORT:-19590}"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
ROUTER_URL="${KCC_LIVE_URL%/}"
MAC="02:00:00:00:51:03"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/${NAME}.XXXXXX")"
CTR="${NAME}-kcc"
VOLUME="${NAME}-state"
SECRETS=(master-key tls-cert tls-key router-password)
PIDS=()

cleanup() {
  local pid secret
  for pid in "${PIDS[@]}"; do kill -INT "${pid}" 2>/dev/null || true; done
  for pid in "${PIDS[@]}"; do wait "${pid}" 2>/dev/null || true; done
  podman rm -f -t 5 "${CTR}" >/dev/null 2>&1 || true
  podman volume rm -f "${VOLUME}" >/dev/null 2>&1 || true
  for secret in "${SECRETS[@]}"; do podman secret rm "${NAME}-${secret}" >/dev/null 2>&1 || true; done
  if [[ "${KCC_LIVE_E2E_KEEP:-0}" == 1 ]]; then echo "kept ${WORK}"; else rm -rf "${WORK}"; fi
}
trap cleanup EXIT

# Runs one named step; its output goes to a log that is shown when it fails.
step() {
  local name="$1"
  shift
  if "$@" >"${WORK}/step-${name}.log" 2>&1; then
    echo "PASS ${name}"
  else
    echo "FAIL ${name}"
    sed 's/^/    /' "${WORK}/step-${name}.log" | tail -n 40
    exit 1
  fi
}

# Waits up to $1 seconds for a line matching $3 to appear in file $2.
wait_line() {
  local tries=$(($1 * 4))
  while ((tries > 0)); do
    grep -q -- "$3" "$2" 2>/dev/null && return 0
    sleep 0.25
    tries=$((tries - 1))
  done
  return 1
}

# ---------------------------------------------------------------- gates (host side)
python3 - "${KCC_LIVE_TARGET_CONFIG}" "${ROUTER_URL}" <<'EOF'
import sys, tomllib
config = tomllib.load(open(sys.argv[1], "rb"))
wanted = sys.argv[2].rstrip("/")
for router in config.get("routers", []):
    if router.get("url", "").rstrip("/") == wanted:
        sys.exit(0 if router.get("test_device") is True else "refused: profile is not test_device = true")
sys.exit("refused: no router profile for KCC_LIVE_URL")
EOF
SERIAL="$(python3 "${ROOT}/scripts/live/rci.py" "${ROUTER_URL}" "${KCC_LIVE_LOGIN}" \
  "${KCC_LIVE_PASSWORD_FILE}" serial)"
ALLOWED=",${KCC_LIVE_ALLOW_SERIAL// /},"
[[ -n "${SERIAL}" && "${ALLOWED}" == *",${SERIAL},"* ]] \
  || { echo "refused: router serial is not in KCC_LIVE_ALLOW_SERIAL" >&2; exit 1; }
echo "router serial allowlisted (sha256 $(printf '%s' "${SERIAL}" | sha256sum | cut -c1-16))"

# ---------------------------------------------------------------- fake Loki (host loopback)
cargo build --quiet --locked -p kcc-testkit --bin kcc-fake-sinks --manifest-path "${ROOT}/Cargo.toml"
"${TARGET_DIR}/debug/kcc-fake-sinks" >"${WORK}/sinks.out" 2>"${WORK}/sinks.log" &
PIDS+=("$!")
wait_line 30 "${WORK}/sinks.out" "^loki "
LOKI_PORT="$(sed -n 's|^loki http://127.0.0.1:||p' "${WORK}/sinks.out")"

# ---------------------------------------------------------------- container layout
mkdir -p "${WORK}/etc" "${WORK}/tls" "${WORK}/source"
head -c 32 /dev/urandom >"${WORK}/master.key"
chmod 0600 "${WORK}/master.key"
cp "${KCC_LIVE_SOURCE_FILE}" "${WORK}/source/source.txt"
chmod 0644 "${WORK}/source/source.txt"
head -c 18 /dev/urandom | base64 | tr -d '\n/+=' >"${WORK}/etc/smoke.password"
chmod 0644 "${WORK}/etc/smoke.password"
HARDENING=(--read-only --cap-drop=ALL --security-opt no-new-privileges
  --security-opt "seccomp=${SECCOMP}" --memory=256m --memory-swap=256m --pids-limit=128)
podman run --rm --userns=keep-id:uid=65532,gid=65532 "${HARDENING[@]}" --network none \
  -v "${WORK}/tls:/out:Z" "${IMAGE}" tls self-signed --host localhost --out-dir /out >/dev/null
podman secret create "${NAME}-master-key" "${WORK}/master.key" >/dev/null
podman secret create "${NAME}-tls-cert" "${WORK}/tls/kcc-cert.pem" >/dev/null
podman secret create "${NAME}-tls-key" "${WORK}/tls/kcc-key.pem" >/dev/null
podman secret create "${NAME}-router-password" "${KCC_LIVE_PASSWORD_FILE}" >/dev/null
podman volume create "${VOLUME}" >/dev/null
RUNTIME=("${HARDENING[@]}"
  --network "pasta:-T,${LOKI_PORT}"
  -v "${WORK}/etc:/etc/kcc:ro,Z" -v "${WORK}/source:/source:ro,Z" -v "${VOLUME}:/var/lib/kcc:U,Z"
  --secret "${NAME}-master-key,target=/run/secrets/kcc-master-key,uid=65532,gid=65532,mode=0400"
  --secret "${NAME}-tls-cert,target=/run/secrets/kcc-tls-cert,uid=65532,gid=65532,mode=0400"
  --secret "${NAME}-tls-key,target=/run/secrets/kcc-tls-key,uid=65532,gid=65532,mode=0400"
  --secret "${NAME}-router-password,target=/run/secrets/kcc-router-password,uid=65532,gid=65532,mode=0400")

cat >"${WORK}/etc/kcc.toml" <<EOF
[server]
listen_addr = "0.0.0.0"
listen_port = 8443
allowed_origins = ["https://localhost:${WEB_PORT}"]
tls_cert_path = "/run/secrets/kcc-tls-cert"
tls_key_path = "/run/secrets/kcc-tls-key"

[web]
enabled = true
public_url = "https://localhost:${WEB_PORT}"

[state]
dir = "/var/lib/kcc"

[metrics]
enabled = true
bind = "0.0.0.0:9090"
allow_non_loopback = true
interval = "15s"

[logs]
enabled = true

[[logs.sinks]]
kind = "loki"
url = "http://127.0.0.1:${LOKI_PORT}"

[[routers]]
name = "lab"
url = "${ROUTER_URL}"
login = "${KCC_LIVE_LOGIN}"
password_file = "/run/secrets/kcc-router-password"
test_device = true
EOF
chmod 0644 "${WORK}/etc/kcc.toml"

kcc() { podman exec "${CTR}" /kcc --config /etc/kcc/kcc.toml "$@"; }
kcc_once() { podman run --rm "${RUNTIME[@]}" "${IMAGE}" --config /etc/kcc/kcc.toml "$@"; }
BASE="https://localhost:${WEB_PORT}"
curl_tls() { curl -sS --cacert "${WORK}/tls/kcc-cert.pem" --max-time 20 "$@"; }

# ---------------------------------------------------------------- steps
accounts() {
  kcc_once --password-file /etc/kcc/smoke.password user add smoke --role admin
}

startup() {
  podman run -d --name "${CTR}" "${RUNTIME[@]}" \
    -p "127.0.0.1:${WEB_PORT}:8443" -p "127.0.0.1:${METRICS_PORT}:9090" "${IMAGE}" >/dev/null
  podman logs -f "${CTR}" >"${WORK}/serve.log" 2>&1 &
  PIDS+=("$!")
  wait_line 60 "${WORK}/serve.log" "metrics endpoint listening"
  wait_line 60 "${WORK}/serve.log" "kcc listening"
}

web_login_dashboard() {
  local html csrf code
  html="$(curl_tls -c "${WORK}/jar" -b "${WORK}/jar" "${BASE}/ui/login")"
  csrf="$(sed -n 's/.*<meta name="csrf-token" content="\([^"]*\)".*/\1/p' <<<"${html}" | head -n 1)"
  [[ -n "${csrf}" ]]
  code="$(curl_tls -c "${WORK}/jar" -b "${WORK}/jar" -o /dev/null -w '%{http_code}' \
    -H "Origin: ${BASE}" -H 'sec-fetch-site: same-origin' -H "x-csrf-token: ${csrf}" \
    --data-urlencode username=smoke --data-urlencode "password@${WORK}/etc/smoke.password" \
    "${BASE}/ui/login")"
  echo "login: ${code}"
  [[ "${code}" == 303 ]]
  code="$(curl_tls -b "${WORK}/jar" -o /dev/null -w '%{http_code}' "${BASE}/ui/r/lab")"
  echo "dashboard: ${code}"
  [[ "${code}" == 200 ]]
}

reversible_write() {
  kcc --router lab --yes clients register --mac "${MAC}" --name kcc-live-51
  kcc --router lab --json clients list | grep -q "${MAC}"
  kcc --router lab --yes clients remove --mac "${MAC}"
  if kcc --router lab --json clients list | jq -e --arg mac "${MAC}" \
    '[.. | objects | select(.mac? == $mac and .registered? == true)] | length > 0' >/dev/null; then
    echo "known host still registered"
    return 1
  fi
}

metrics_scrape() {
  local scrape="${WORK}/metrics.prom"
  for _ in $(seq 1 30); do
    curl -sS --max-time 10 "http://127.0.0.1:${METRICS_PORT}/metrics" >"${scrape}"
    grep -q 'keenetic_up{router="lab"} 1' "${scrape}" && break
    sleep 2
  done
  grep 'keenetic_up{router="lab"} 1' "${scrape}"
  grep -c '^keenetic_' "${scrape}"
}

log_forwarding() {
  wait_line 120 "${WORK}/sinks.log" 'sink requests.*loki=[1-9]'
  grep 'sink requests' "${WORK}/sinks.log" | tail -n 1
}

copy_rollback() {
  local result
  result="$(kcc --json copy --from file:/source/source.txt --to lab --groups dns-secure \
    --yes --finish rollback)"
  echo "${result}"
  jq -e '.verified and .finish == "rollback"' <<<"${result}" >/dev/null
}

denials() {
  local logs=("${WORK}/serve.log") log
  for log in "${WORK}"/step-*.log; do
    [[ "${log}" == */step-no-denials.log ]] || logs+=("${log}")
  done
  if grep -E 'Operation not permitted|EPERM|ENOSYS|os error 1\)|os error 38' "${logs[@]}"; then
    return 1
  fi
  echo "no seccomp denial in the server log or any step output"
}

step accounts accounts
step startup startup
step web-login-dashboard web_login_dashboard
step reversible-write reversible_write
step metrics-scrape metrics_scrape
step log-forwarding log_forwarding
step copy-rollback copy_rollback
step no-denials denials
echo "live-e2e: all steps passed"
