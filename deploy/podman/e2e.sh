#!/usr/bin/env bash
# End-to-end drive of every kcc I/O path, natively (for syscall tracing) or against the
# hardened container. The fake routers and the fake Loki/Elasticsearch sinks run on the
# host loopback from the kcc-testkit binaries; the container reaches them on its own
# loopback through pasta's `-T` port forwards (the routers under a hostname added with
# `--add-host`, so the name is resolved; the sinks under 127.0.0.1, because a plain-HTTP
# sink must be a loopback test sink).
#
#   deploy/podman/e2e.sh --native <kcc-binary> [--trace-dir <dir>]
#   deploy/podman/e2e.sh --container [--image <ref>] [--seccomp <profile.json>]
#   options: --keep-going (report every step instead of stopping at the first failure)
#
# Environment: CARGO_TARGET_DIR (testkit binaries), KCC_E2E_NAME (prefix of every podman
# object, default kcc-e2e), KCC_E2E_WEB_PORT (default 18443), KCC_E2E_METRICS_PORT
# (default 19090), KCC_E2E_ROUTER_PORT (first of two fake router ports, default 18481),
# KCC_E2E_KEEP=1 (keep the work directory with every log), KCC_E2E_VERBOSE=1 (print the
# output of passing steps too).
# The container never runs as root, never gains a capability and always runs under the
# seccomp profile.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE=""
BIN=""
IMAGE="kcc:test"
SECCOMP="${ROOT}/deploy/podman/seccomp-kcc.json"
TRACE_DIR=""
KEEP_GOING=0
while (($# > 0)); do
  case "$1" in
    --native) MODE=native; BIN="$(realpath "$2")"; shift 2 ;;
    --container) MODE=container; shift ;;
    --image) IMAGE="$2"; shift 2 ;;
    --seccomp) SECCOMP="$(realpath "$2")"; shift 2 ;;
    --trace-dir) TRACE_DIR="$(realpath -m "$2")"; shift 2 ;;
    --keep-going) KEEP_GOING=1; shift ;;
    *) echo "usage: $0 --native <kcc> [--trace-dir <dir>] | --container [--image <ref>] [--seccomp <json>] [--keep-going]" >&2; exit 2 ;;
  esac
done
[[ -n "${MODE}" ]] || { echo "pass --native <kcc> or --container" >&2; exit 2; }

NAME="${KCC_E2E_NAME:-kcc-e2e}"
WEB_PORT="${KCC_E2E_WEB_PORT:-18443}"
METRICS_PORT="${KCC_E2E_METRICS_PORT:-19090}"
ROUTER_A_PORT="${KCC_E2E_ROUTER_PORT:-18481}"
ROUTER_B_PORT="$((ROUTER_A_PORT + 1))"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/${NAME}.XXXXXX")"
CTR="${NAME}-kcc"
VOLUME="${NAME}-state"
SECRETS=(master-key tls-cert tls-key router-password user-password)
PIDS=()
FAILED=0

# Prints the PIDs of every descendant of $1, deepest first.
descendants() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null || true); do
    descendants "${child}"
    echo "${child}"
  done
}

# True while process $1 exists and is not a zombie waiting to be reaped.
is_running() {
  local state
  state="$(ps -o stat= -p "$1" 2>/dev/null)" || return 1
  [[ "${state}" != Z* ]]
}

# Stops every background process. A traced server runs under a bash wrapper whose
# SIGINT is ignored (background jobs), so the whole process tree gets SIGTERM, then
# SIGKILL after a bounded wait.
stop_background() {
  local pid tree=() alive i
  for pid in "${PIDS[@]}"; do
    mapfile -t -O "${#tree[@]}" tree < <(descendants "${pid}")
    tree+=("${pid}")
  done
  ((${#tree[@]} > 0)) || return 0
  kill -TERM "${tree[@]}" 2>/dev/null || true
  for ((i = 0; i < 40; i++)); do
    alive=0
    for pid in "${tree[@]}"; do ! is_running "${pid}" || alive=1; done
    ((alive == 1)) || break
    sleep 0.25
  done
  kill -KILL "${tree[@]}" 2>/dev/null || true
  for pid in "${PIDS[@]}"; do wait "${pid}" 2>/dev/null || true; done
}

cleanup() {
  stop_background
  if [[ "${MODE}" == container ]]; then
    podman rm -f -t 5 "${CTR}" >/dev/null 2>&1 || true
    podman volume rm -f "${VOLUME}" >/dev/null 2>&1 || true
    local secret
    for secret in "${SECRETS[@]}"; do podman secret rm "${NAME}-${secret}" >/dev/null 2>&1 || true; done
  fi
  if [[ "${KCC_E2E_KEEP:-0}" == 1 ]]; then
    echo "kept ${WORK}"
  else
    rm -rf "${WORK}"
  fi
}
trap cleanup EXIT

# Runs one named step; its output goes to a log that is shown when it fails. The step
# runs in a subshell with errexit on: a function called from an `if` condition would
# ignore `set -e`, so only its last command would decide the result. A step therefore
# cannot set variables for later steps (the server is launched by launch_server).
step() {
  local name="$1" log rc
  shift
  log="${WORK}/step-${name}.log"
  set +e
  ( set -e; "$@" ) >"${log}" 2>&1
  rc=$?
  set -e
  if ((rc == 0)); then
    echo "PASS ${name}"
    if [[ "${KCC_E2E_VERBOSE:-0}" == 1 ]]; then
      sed 's/^/    /' "${log}" | tail -n 12
    fi
  else
    echo "FAIL ${name}"
    sed 's/^/    /' "${log}" | tail -n 40
    FAILED=$((FAILED + 1))
    ((KEEP_GOING == 1)) || exit 1
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

# ---------------------------------------------------------------- host-side fakes
echo "building the kcc-testkit fakes"
cargo build --quiet --locked -p kcc-testkit --bin kcc-fake-router --bin kcc-fake-sinks \
  --manifest-path "${ROOT}/Cargo.toml"
printf 'e2e-router-password\n' >"${WORK}/router.password"
for side in a b; do
  port="${ROUTER_A_PORT}"
  [[ "${side}" == b ]] && port="${ROUTER_B_PORT}"
  "${TARGET_DIR}/debug/kcc-fake-router" --model KN-1811 --firmware 5.1 --mode router --seed-log 3 \
    --bind "127.0.0.1:${port}" --password-file "${WORK}/router.password" \
    >"${WORK}/router-${side}.log" 2>&1 &
  PIDS+=("$!")
done
NO_COLOR=1 "${TARGET_DIR}/debug/kcc-fake-sinks" >"${WORK}/sinks.out" 2>"${WORK}/sinks.log" &
PIDS+=("$!")
wait_line 30 "${WORK}/router-a.log" "fake router listening"
wait_line 30 "${WORK}/router-b.log" "fake router listening"
wait_line 30 "${WORK}/sinks.out" "^elasticsearch "
LOKI_PORT="$(sed -n 's|^loki http://127.0.0.1:||p' "${WORK}/sinks.out")"
ES_PORT="$(sed -n 's|^elasticsearch http://127.0.0.1:||p' "${WORK}/sinks.out")"

# ---------------------------------------------------------------- mode-specific layout
mkdir -p "${WORK}/etc" "${WORK}/tls"
head -c 32 /dev/urandom >"${WORK}/master.key"
chmod 0600 "${WORK}/master.key" "${WORK}/router.password"
printf '%s' 'e2e-web-password-1234' >"${WORK}/etc/e2e-user.password"
chmod 0600 "${WORK}/etc/e2e-user.password"
if [[ "${MODE}" == native ]]; then
  HOST_NAME="localhost"
  LISTEN="127.0.0.1"
  LISTEN_PORT="${WEB_PORT}"
  METRICS_BIND="127.0.0.1:${METRICS_PORT}"
  CONF="${WORK}/etc/kcc.toml"
  STATE="${WORK}/state"
  CERT="${WORK}/tls/kcc-cert.pem"
  KEY="${WORK}/tls/kcc-key.pem"
  ROUTER_PASSWORD="${WORK}/router.password"
  USER_PASSWORD="${WORK}/etc/e2e-user.password"
  export HOME="${WORK}/home" XDG_CONFIG_HOME="${WORK}/home/config" \
    XDG_STATE_HOME="${WORK}/home/state" KCC_MASTER_KEY_FILE="${WORK}/master.key"
  WRAP=()
  if [[ -n "${TRACE_DIR}" ]]; then
    mkdir -p "${TRACE_DIR}"
    WRAP=(strace -f -qq -ff -o "${TRACE_DIR}/trace")
  fi
  "${BIN}" tls self-signed --host localhost --out-dir "${WORK}/tls" >/dev/null
  kcc_cfg() { "${WRAP[@]}" "${BIN}" --config "$@"; }
  kcc_once() { kcc "$@"; }
else
  HOST_NAME="fakes.kcc-e2e.test"
  FORWARDS="-T,${ROUTER_A_PORT},-T,${ROUTER_B_PORT},-T,${LOKI_PORT},-T,${ES_PORT}"
  LISTEN="0.0.0.0"
  LISTEN_PORT=8443
  METRICS_BIND="0.0.0.0:9090"
  CONF="/etc/kcc/kcc.toml"
  STATE="/var/lib/kcc"
  CERT="${WORK}/tls/kcc-cert.pem"
  KEY="/run/secrets/kcc-tls-key"
  ROUTER_PASSWORD="/run/secrets/kcc-router-password"
  # kcc refuses a password file others can read, and a 0600 bind mount is owned by the
  # container's root, so the password reaches the image user as a secret.
  USER_PASSWORD="/run/secrets/kcc-user-password"
  # The certificate is generated by the image itself, as the non-root image user mapped
  # onto the invoking host user, so the files stay owned by that host user.
  podman run --rm --userns=keep-id:uid=65532,gid=65532 --read-only --cap-drop=ALL \
    --security-opt no-new-privileges --security-opt "seccomp=${SECCOMP}" --network none \
    -v "${WORK}/tls:/out:Z" "${IMAGE}" tls self-signed --host localhost --out-dir /out >/dev/null
  podman secret create "${NAME}-master-key" "${WORK}/master.key" >/dev/null
  podman secret create "${NAME}-tls-cert" "${WORK}/tls/kcc-cert.pem" >/dev/null
  podman secret create "${NAME}-tls-key" "${WORK}/tls/kcc-key.pem" >/dev/null
  podman secret create "${NAME}-router-password" "${WORK}/router.password" >/dev/null
  podman secret create "${NAME}-user-password" "${WORK}/etc/e2e-user.password" >/dev/null
  podman volume create "${VOLUME}" >/dev/null
  HARDENING=(--read-only --cap-drop=ALL --security-opt no-new-privileges
    --security-opt "seccomp=${SECCOMP}" --memory=256m --memory-swap=256m --pids-limit=128)
  RUNTIME=("${HARDENING[@]}"
    --network "pasta:${FORWARDS}"
    --add-host "${HOST_NAME}:127.0.0.1"
    -v "${WORK}/etc:/etc/kcc:ro,Z" -v "${VOLUME}:/var/lib/kcc:U,Z"
    --secret "${NAME}-master-key,target=/run/secrets/kcc-master-key,uid=65532,gid=65532,mode=0400"
    --secret "${NAME}-tls-cert,target=/run/secrets/kcc-tls-cert,uid=65532,gid=65532,mode=0400"
    --secret "${NAME}-tls-key,target=/run/secrets/kcc-tls-key,uid=65532,gid=65532,mode=0400"
    --secret "${NAME}-router-password,target=/run/secrets/kcc-router-password,uid=65532,gid=65532,mode=0400"
    --secret "${NAME}-user-password,target=/run/secrets/kcc-user-password,uid=65532,gid=65532,mode=0400")
  kcc_cfg() { podman exec "${CTR}" /kcc --config "$@"; }
  kcc_once() { podman run --rm "${RUNTIME[@]}" "${IMAGE}" --config "${CONF}" "$@"; }
fi
kcc() { kcc_cfg "${CONF}" "$@"; }
CERT_IN="${CERT}"
[[ "${MODE}" == container ]] && CERT_IN="/run/secrets/kcc-tls-cert"

cat >"${WORK}/etc/kcc.toml" <<EOF
[server]
listen_addr = "${LISTEN}"
listen_port = ${LISTEN_PORT}
# Keep one explicit entry to exercise union with the origin derived from [web].
allowed_origins = ["https://localhost:${WEB_PORT}"]
tls_cert_path = "${CERT_IN}"
tls_key_path = "${KEY}"

[web]
enabled = true
public_url = "https://localhost:${WEB_PORT}"

[mcp]
http_enabled = true

[outbound]
allow_loopback = true

[state]
dir = "${STATE}"

[metrics]
enabled = true
bind = "${METRICS_BIND}"
allow_non_loopback = $([[ "${MODE}" == container ]] && echo true || echo false)
interval = "15s"

[logs]
enabled = true

[[logs.sinks]]
kind = "loki"
url = "http://127.0.0.1:${LOKI_PORT}"

[[logs.sinks]]
kind = "elasticsearch"
url = "http://127.0.0.1:${ES_PORT}"

[[routers]]
name = "fake-a"
url = "http://${HOST_NAME}:${ROUTER_A_PORT}"
login = "admin"
password_file = "${ROUTER_PASSWORD}"

[[routers]]
name = "fake-b"
url = "http://${HOST_NAME}:${ROUTER_B_PORT}"
login = "admin"
password_file = "${ROUTER_PASSWORD}"
EOF
# A separate configuration for the resolver probe: a router whose name does not resolve
# would stop `kcc serve` at startup.
cat >"${WORK}/etc/dns-probe.toml" <<EOF
[state]
dir = "${STATE}"

[[routers]]
name = "dns-probe"
url = "http://kcc-e2e-dns-probe.invalid"
login = "admin"
password_file = "${ROUTER_PASSWORD}"
EOF
chmod 0644 "${WORK}/etc/kcc.toml" "${WORK}/etc/dns-probe.toml"

BASE="https://localhost:${WEB_PORT}"
curl_tls() { curl -sS --cacert "${CERT}" --max-time 20 "$@"; }

# ---------------------------------------------------------------- steps
privilege_floor() {
  kcc_once --version
  if [[ "${MODE}" == container ]]; then
    local code=0
    podman run --rm --user 0 "${HARDENING[@]}" --network none "${IMAGE}" --version || code=$?
    echo "as root: exit ${code}"
    [[ "${code}" == 77 ]]
  fi
}

accounts() {
  kcc_once --json admin init --username admin >"${WORK}/admin.json"
  kcc_once --password-file "${USER_PASSWORD}" user add e2e --role admin
  kcc_once --json apikey create e2e-mcp --role operator >"${WORK}/apikey.json"
}

# Starts the server in the background. It runs at the top level, not inside a step, so
# that PIDS stays visible to cleanup.
launch_server() {
  if [[ "${MODE}" == native ]]; then
    # The exit status goes to a file: a step runs in a subshell and cannot `wait` for it.
    {
      local code=0
      kcc serve >"${WORK}/serve.log" 2>&1 || code=$?
      echo "${code}" >"${WORK}/serve.exit"
    } &
    PIDS+=("$!")
  else
    podman run -d --name "${CTR}" "${RUNTIME[@]}" \
      -p "127.0.0.1:${WEB_PORT}:8443" -p "127.0.0.1:${METRICS_PORT}:9090" "${IMAGE}" >/dev/null \
      || return 1
    podman logs -f "${CTR}" >"${WORK}/serve.log" 2>&1 &
    PIDS+=("$!")
    podman inspect --format 'user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_add={{.HostConfig.CapAdd}} cap_drop={{.HostConfig.CapDrop}} security_opt={{.HostConfig.SecurityOpt}} memory={{.HostConfig.Memory}} memory_swap={{.HostConfig.MemorySwap}} pids_limit={{.HostConfig.PidsLimit}} ports={{.HostConfig.PortBindings}}' "${CTR}"
  fi
}

startup() {
  if ! wait_line 60 "${WORK}/serve.log" "metrics endpoint listening" \
    || ! wait_line 60 "${WORK}/serve.log" "Web UI\|listening on\|\"listening\""; then
    tail -n 40 "${WORK}/serve.log"
    return 1
  fi
}

healthz() {
  local code
  code="$(curl_tls -o /dev/null -w '%{http_code}' "${BASE}/healthz")"
  [[ "${code}" == 200 ]]
}

tls_handshake() {
  curl_tls -v -o /dev/null "${BASE}/ui/login" 2>&1 | grep -E 'SSL connection using TLSv1\.[23]|subject:'
}

web_login() {
  local html csrf code
  html="$(curl_tls -c "${WORK}/jar" -b "${WORK}/jar" "${BASE}/ui/login")"
  csrf="$(sed -n 's/.*<meta name="csrf-token" content="\([^"]*\)".*/\1/p' <<<"${html}" | head -n 1)"
  [[ -n "${csrf}" ]]
  code="$(curl_tls -c "${WORK}/jar" -b "${WORK}/jar" -o /dev/null -w '%{http_code}' \
    -H "Origin: ${BASE}" -H 'sec-fetch-site: same-origin' -H "x-csrf-token: ${csrf}" \
    --data-urlencode username=e2e --data-urlencode "password@${WORK}/etc/e2e-user.password" \
    "${BASE}/ui/login")"
  echo "login: ${code}"
  [[ "${code}" == 303 ]]
  code="$(curl_tls -b "${WORK}/jar" -o /dev/null -w '%{http_code}' "${BASE}/ui/r/fake-a")"
  echo "dashboard: ${code}"
  [[ "${code}" == 200 ]]
}

dashboard_sse() {
  (curl -sS -N --cacert "${CERT}" --max-time 60 -b "${WORK}/jar" "${BASE}/ui/sse/fleet" || true) \
    | grep -m1 '^data:' | head -c 200
}

router_connect() {
  kcc --router fake-a --json system version
}

domain_write_save() {
  kcc --router fake-a --yes system set-description kcc-e2e-description
  # A line the target lacks, so the migration below has something to apply.
  kcc --router fake-a --yes dns static-host nas.kcc-e2e.test 192.0.2.40
  kcc --router fake-a --yes config save
  kcc --router fake-a --json config state
}

dns_lookup() {
  # A real resolver query (NXDOMAIN): proves the DNS path, the step expects the refusal.
  local code=0
  kcc_cfg "$(dirname "${CONF}")/dns-probe.toml" --json system version || code=$?
  echo "dns-probe exit ${code}"
  [[ "${code}" != 0 ]]
}

migration() {
  local planned applied
  planned="$(kcc --router fake-b --json migrate plan --from router:fake-a \
    --out "${STATE}/e2e-plan.json")"
  echo "${planned}"
  applied="$(kcc --router fake-b --yes --json migrate apply --from router:fake-a \
    --plan "${STATE}/e2e-plan.json" --finish commit)"
  echo "${applied}"
  jq -e '.lines > 0' <<<"${planned}" >/dev/null
  jq -e '.applied > 0 and .failed == 0 and .verified and .finish == "commit"' <<<"${applied}" >/dev/null
}

backup_download() {
  local name code
  kcc --router fake-a --json backup create --reason e2e
  name="$(kcc --router fake-a --json backup list | jq -r '.backups[0].name')"
  [[ -n "${name}" ]]
  code="$(curl_tls -b "${WORK}/jar" -o "${WORK}/backup.txt" -w '%{http_code}' \
    "${BASE}/ui/r/fake-a/config/backups/download?name=${name}")"
  echo "download ${name}: ${code}, $(wc -c <"${WORK}/backup.txt") bytes"
  [[ "${code}" == 200 && -s "${WORK}/backup.txt" ]]
}

metrics_scrape() {
  local scrape="${WORK}/metrics.prom"
  for _ in $(seq 1 30); do
    curl -sS --max-time 10 "http://127.0.0.1:${METRICS_PORT}/metrics" >"${scrape}"
    grep -q 'keenetic_up{router="fake-a"} 1' "${scrape}" && break
    sleep 2
  done
  grep 'keenetic_up{' "${scrape}"
  grep -q 'keenetic_up{router="fake-a"} 1' "${scrape}"
  promtool check metrics <"${scrape}"
  echo "promtool check metrics: OK ($(wc -l <"${scrape}") lines from 127.0.0.1:${METRICS_PORT})"
}

log_forwarding() {
  wait_line 120 "${WORK}/sinks.log" 'sink requests.*loki=[1-9].*elasticsearch=[1-9]'
  grep 'sink requests' "${WORK}/sinks.log" | tail -n 1
}

mcp_json() {
  curl_tls -D "${WORK}/mcp.headers" -H "Authorization: Bearer ${MCP_KEY}" \
    -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
    ${MCP_SESSION:+-H "Mcp-Session-Id: ${MCP_SESSION}"} --data "$1" "${BASE}/mcp"
}

mcp_http() {
  MCP_KEY="$(jq -r '.key' "${WORK}/apikey.json")"
  MCP_SESSION=""
  mcp_json '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}' >/dev/null
  MCP_SESSION="$(sed -n 's/^mcp-session-id: *\([^[:space:]]*\).*/\1/Ip' "${WORK}/mcp.headers")"
  [[ -n "${MCP_SESSION}" ]]
  mcp_json '{"jsonrpc":"2.0","method":"notifications/initialized"}' >/dev/null
  mcp_json '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | grep -o '"kcc_router_info"' | head -n 1
  mcp_json '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"kcc_router_info","arguments":{"host":"fake-a"}}}' \
    | tee "${WORK}/mcp-call.txt" | grep -q '"isError":false'
}

healthcheck() {
  if [[ "${MODE}" == native ]]; then
    kcc healthcheck
  else
    podman healthcheck run "${CTR}"
    local status
    status="$(podman inspect --format '{{.State.Health.Status}}' "${CTR}")"
    echo "health: ${status}"
    [[ "${status}" == healthy ]]
  fi
}

sighup_reload() {
  if [[ "${MODE}" == native ]]; then
    kill -HUP "$(pgrep -f "^${BIN} --config ${CONF} serve" | head -n 1)"
  else
    podman kill --signal HUP "${CTR}" >/dev/null
  fi
  wait_line 30 "${WORK}/serve.log" "configuration reloaded from SIGHUP"
  healthz
}

graceful_sigterm() {
  local code=0
  if [[ "${MODE}" == native ]]; then
    local pid
    pid="$(pgrep -f "^${BIN} --config ${CONF} serve" | head -n 1)"
    kill -TERM "${pid}"
    wait_line 30 "${WORK}/serve.exit" '^[0-9]'
    code="$(<"${WORK}/serve.exit")"
  else
    podman stop -t 30 "${CTR}" >/dev/null
    code="$(podman inspect --format '{{.State.ExitCode}}' "${CTR}")"
  fi
  echo "serve exit ${code}"
  [[ "${code}" == 0 ]]
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

step privilege-floor privilege_floor
step accounts accounts
if ! launch_server >"${WORK}/step-startup-launch.log" 2>&1; then
  echo "FAIL startup"
  tail -n 40 "${WORK}/step-startup-launch.log" | sed 's/^/    /'
  exit 1
fi
step startup startup
step healthz healthz
step tls-handshake tls_handshake
step web-login web_login
step dashboard-sse dashboard_sse
step router-connect router_connect
step domain-write-save domain_write_save
step dns-lookup dns_lookup
step migration migration
step backup-download backup_download
step metrics-scrape metrics_scrape
step log-forwarding log_forwarding
step mcp-http mcp_http
step healthcheck healthcheck
step sighup-reload sighup_reload
step graceful-sigterm graceful_sigterm
step no-denials denials
if ((FAILED > 0)); then
  echo "e2e: ${FAILED} step(s) failed"
  exit 1
fi
echo "e2e: all steps passed (${MODE})"
