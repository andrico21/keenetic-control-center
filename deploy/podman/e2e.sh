#!/usr/bin/env bash
# End-to-end drive of every kcc I/O path, natively (for syscall tracing) or against the
# hardened container. The fake routers and the fake Loki/Elasticsearch/Telegram sinks run
# on the host loopback from the kcc-testkit binaries; the container reaches them on its own
# loopback through pasta's `-T` port forwards (the routers under a hostname added with
# `--add-host`, so the name is resolved; the sinks under 127.0.0.1, because a plain-HTTP
# sink must be a loopback test sink).
#
#   deploy/podman/e2e.sh --native <kcc-binary> [--trace-dir <dir>]
#   deploy/podman/e2e.sh --container [--image <ref>] [--seccomp <profile.json>]
#   options: --keep-going (report every step instead of stopping at the first failure)
#            --only <step>[,<step>...] (run only these steps after the start-up steps;
#            mcp-oauth brings mcp-main-restart, which switches the main listener to it)
#
# Environment: CARGO_TARGET_DIR (testkit binaries), KCC_E2E_NAME (prefix of every podman
# object, default kcc-e2e), KCC_E2E_WEB_PORT (default 18443), KCC_E2E_METRICS_PORT
# (default 19090), KCC_E2E_ROUTER_PORT (first of two fake router ports, default 18481),
# KCC_E2E_SSH_PORT (the fake Entware SSH server of the first router, default 18422),
# KCC_E2E_MCP_PORT (the dedicated MCP listener, default 18444), KCC_E2E_KEEP=1 (keep the
# work directory with every log), KCC_E2E_VERBOSE=1 (print the output of passing steps
# too).
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
ONLY=""
while (($# > 0)); do
  case "$1" in
    --native) MODE=native; BIN="$(realpath "$2")"; shift 2 ;;
    --container) MODE=container; shift ;;
    --image) IMAGE="$2"; shift 2 ;;
    --seccomp) SECCOMP="$(realpath "$2")"; shift 2 ;;
    --trace-dir) TRACE_DIR="$(realpath -m "$2")"; shift 2 ;;
    --keep-going) KEEP_GOING=1; shift ;;
    --only) ONLY=",$2,"; shift 2 ;;
    *) echo "usage: $0 --native <kcc> [--trace-dir <dir>] | --container [--image <ref>] [--seccomp <json>] [--keep-going] [--only <steps>]" >&2; exit 2 ;;
  esac
done
[[ -n "${MODE}" ]] || { echo "pass --native <kcc> or --container" >&2; exit 2; }
if [[ "${ONLY}" == *,mcp-oauth,* && "${ONLY}" != *,mcp-main-restart,* ]]; then
  ONLY="${ONLY}mcp-main-restart,"
fi

NAME="${KCC_E2E_NAME:-kcc-e2e}"
WEB_PORT="${KCC_E2E_WEB_PORT:-18443}"
METRICS_PORT="${KCC_E2E_METRICS_PORT:-19090}"
ROUTER_A_PORT="${KCC_E2E_ROUTER_PORT:-18481}"
ROUTER_B_PORT="$((ROUTER_A_PORT + 1))"
SSH_PORT="${KCC_E2E_SSH_PORT:-18422}"
MCP_PORT="${KCC_E2E_MCP_PORT:-18444}"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/${NAME}.XXXXXX")"
CTR="${NAME}-kcc"
VOLUME="${NAME}-state"
SECRETS=(master-key tls-cert tls-key router-password user-password telegram-token
  entware-password entware-wrong-password)
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
  case "${name}" in
    privilege-floor | accounts | startup | healthz | graceful-sigterm | no-denials) ;;
    *) [[ -z "${ONLY}" || "${ONLY}" == *",${name},"* ]] || return 0 ;;
  esac
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
  # The first router also serves the fake Entware SSH server (root password `keenetic`).
  ssh=(--entware-ssh-port "${SSH_PORT}")
  if [[ "${side}" == b ]]; then
    port="${ROUTER_B_PORT}"
    ssh=()
  fi
  "${TARGET_DIR}/debug/kcc-fake-router" --model KN-1811 --firmware 5.1 --mode router --seed-log 3 \
    --bind "127.0.0.1:${port}" --password-file "${WORK}/router.password" "${ssh[@]}" \
    >"${WORK}/router-${side}.log" 2>&1 &
  PIDS+=("$!")
done
NO_COLOR=1 "${TARGET_DIR}/debug/kcc-fake-sinks" >"${WORK}/sinks.out" 2>"${WORK}/sinks.log" &
PIDS+=("$!")
wait_line 30 "${WORK}/router-a.log" "fake router listening"
wait_line 30 "${WORK}/router-b.log" "fake router listening"
wait_line 30 "${WORK}/router-a.log" "fake Entware SSH listening"
wait_line 30 "${WORK}/sinks.out" "^elasticsearch "
wait_line 30 "${WORK}/sinks.out" "^telegram "
LOKI_PORT="$(sed -n 's|^loki http://127.0.0.1:||p' "${WORK}/sinks.out")"
ES_PORT="$(sed -n 's|^elasticsearch http://127.0.0.1:||p' "${WORK}/sinks.out")"
TELEGRAM_PORT="$(sed -n 's|^telegram http://127.0.0.1:||p' "${WORK}/sinks.out")"

# ---------------------------------------------------------------- mode-specific layout
mkdir -p "${WORK}/etc" "${WORK}/tls"
head -c 32 /dev/urandom >"${WORK}/master.key"
chmod 0600 "${WORK}/master.key" "${WORK}/router.password"
printf '%s' 'e2e-web-password-1234' >"${WORK}/etc/e2e-user.password"
chmod 0600 "${WORK}/etc/e2e-user.password"
# An obviously fake bot token in the shape kcc accepts; the fake Telegram takes any token.
printf '%s' '0:e2e-fake-token-not-a-real-telegram-bot' >"${WORK}/telegram.token"
chmod 0600 "${WORK}/telegram.token"
printf '%s' 'keenetic' >"${WORK}/entware.password"
printf '%s' 'not-the-entware-password' >"${WORK}/entware-wrong.password"
chmod 0600 "${WORK}/entware.password" "${WORK}/entware-wrong.password"
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
  TELEGRAM_TOKEN="${WORK}/telegram.token"
  ENTWARE_PASSWORD="${WORK}/entware.password"
  ENTWARE_WRONG_PASSWORD="${WORK}/entware-wrong.password"
  MCP_BIND="127.0.0.1"
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
  FORWARDS="-T,${ROUTER_A_PORT},-T,${ROUTER_B_PORT},-T,${SSH_PORT},-T,${LOKI_PORT},-T,${ES_PORT},-T,${TELEGRAM_PORT}"
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
  TELEGRAM_TOKEN="/run/secrets/kcc-telegram-token"
  ENTWARE_PASSWORD="/run/secrets/kcc-entware-password"
  ENTWARE_WRONG_PASSWORD="/run/secrets/kcc-entware-wrong-password"
  # Published like the Web UI, so the listener binds the container's interface.
  MCP_BIND="0.0.0.0"
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
  podman secret create "${NAME}-telegram-token" "${WORK}/telegram.token" >/dev/null
  podman secret create "${NAME}-entware-password" "${WORK}/entware.password" >/dev/null
  podman secret create "${NAME}-entware-wrong-password" "${WORK}/entware-wrong.password" >/dev/null
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
    --secret "${NAME}-user-password,target=/run/secrets/kcc-user-password,uid=65532,gid=65532,mode=0400"
    --secret "${NAME}-telegram-token,target=/run/secrets/kcc-telegram-token,uid=65532,gid=65532,mode=0400"
    --secret "${NAME}-entware-password,target=/run/secrets/kcc-entware-password,uid=65532,gid=65532,mode=0400"
    --secret "${NAME}-entware-wrong-password,target=/run/secrets/kcc-entware-wrong-password,uid=65532,gid=65532,mode=0400")
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
endpoint = "both"

[mcp.dedicated]
enabled = true
bind = "${MCP_BIND}"
port = ${MCP_PORT}
public_url = "https://localhost:${MCP_PORT}"
tls = "self_signed"

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

[notify.telegram]
api_url = "http://127.0.0.1:${TELEGRAM_PORT}"

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
  kcc_once notify token --file "${TELEGRAM_TOKEN}"
  kcc_once notify chat add 1001 --label e2e
  # Only the scheduled-run success: no other event can add a message the steps count.
  kcc_once notify events scheduled_success
  kcc_once notify enable
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
      -p "127.0.0.1:${WEB_PORT}:8443" -p "127.0.0.1:${METRICS_PORT}:9090" \
      -p "127.0.0.1:${MCP_PORT}:${MCP_PORT}" "${IMAGE}" >/dev/null \
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

# The Telegram request count of the last `sink requests` line of the fake sinks, 0 before
# the first.
telegram_count() {
  local count
  count="$(sed -n 's/.*sink requests.*telegram=\([0-9][0-9]*\).*/\1/p' "${WORK}/sinks.log" | tail -n 1)"
  echo "${count:-0}"
}

# Waits up to $1 seconds for the fake Telegram to count more than $2 requests.
wait_telegram_above() {
  local tries=$(($1 * 4))
  while ((tries > 0)); do
    (($(telegram_count) > $2)) && return 0
    sleep 0.25
    tries=$((tries - 1))
  done
  return 1
}

telegram_test_message() {
  local before
  before="$(telegram_count)"
  # The CLI reads the state the running server uses and sends straight to the fake.
  kcc --json notify test | tee "${WORK}/notify-test.json"
  jq -e '.sent and .chat == "1001"' "${WORK}/notify-test.json" >/dev/null
  wait_telegram_above 30 "${before}"
  grep 'sink requests' "${WORK}/sinks.log" | tail -n 1
}

# A count of fake-a's backups.
backup_count() {
  kcc --router fake-a --json backup list | jq '.backups | length'
}

schedule_run_now() {
  local html csrf code id backups messages tries
  html="$(curl_tls -b "${WORK}/jar" "${BASE}/ui/admin/scheduled")"
  csrf="$(sed -n 's/.*<meta name="csrf-token" content="\([^"]*\)".*/\1/p' <<<"${html}" | head -n 1)"
  [[ -n "${csrf}" ]]
  # A slot twelve hours away, so only the run-now below runs it.
  code="$(curl_tls -b "${WORK}/jar" -o "${WORK}/schedule-create.html" -w '%{http_code}' \
    -H "Origin: ${BASE}" -H 'sec-fetch-site: same-origin' -H "x-csrf-token: ${csrf}" \
    -H 'hx-request: true' \
    --data-urlencode name=e2e-backup --data-urlencode router=fake-a \
    --data-urlencode days=mon --data-urlencode days=thu \
    --data-urlencode "hour=$((($(date -u +%-H) + 12) % 24))" --data-urlencode minute=0 \
    --data-urlencode zone=UTC --data-urlencode kind=backup \
    "${BASE}/ui/admin/scheduled")"
  echo "create: ${code}"
  [[ "${code}" == 200 ]]
  id="$(kcc --json scheduled list \
    | jq -r '.schedules[] | select(.name == "e2e-backup" and .router == "fake-a") | .id')"
  echo "schedule: ${id}"
  [[ -n "${id}" ]]
  backups="$(backup_count)"
  messages="$(telegram_count)"
  code="$(curl_tls -b "${WORK}/jar" -o "${WORK}/schedule-run.html" -w '%{http_code}' \
    -H "Origin: ${BASE}" -H 'sec-fetch-site: same-origin' -H "x-csrf-token: ${csrf}" \
    -H 'hx-request: true' --data-urlencode confirm=yes \
    "${BASE}/ui/admin/scheduled/run-now?id=${id}")"
  echo "run-now: ${code}"
  [[ "${code}" == 200 ]]
  # The run goes on in the background: poll its backup, then its Telegram message.
  for ((tries = 60; tries > 0; tries--)); do
    (($(backup_count) > backups)) && break
    sleep 1
  done
  echo "backups of fake-a: ${backups} -> $(backup_count)"
  (($(backup_count) > backups))
  wait_telegram_above 90 "${messages}"
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

# ---------------------------------------------------------------- Entware SSH leg
# Every Entware SSH command needs the destructive confirmation, reads included.
entware() { kcc --router fake-a --json --confirm-destructive fake-a "$@"; }

# Probes the fake's host key into ${WORK}/ssh-probe.json (the ticket stays out of the log).
entware_probe() {
  entware entware ssh probe >"${WORK}/ssh-probe.json"
  jq -e '.ticket and (.fingerprint | startswith("SHA256:"))' "${WORK}/ssh-probe.json" >/dev/null
}

# Bootstraps with the ticket of the last probe and the Entware password file $1.
entware_bootstrap() {
  entware --password-file "$1" entware ssh bootstrap \
    --ticket "$(jq -r '.ticket' "${WORK}/ssh-probe.json")" \
    --fingerprint "$(jq -r '.fingerprint' "${WORK}/ssh-probe.json")"
}

entware_ssh() {
  local code=0
  entware entware ssh enable --port "${SSH_PORT}"
  entware_probe
  # A wrong root password is refused (exit 3) and burns the ticket: probe again.
  entware_bootstrap "${ENTWARE_WRONG_PASSWORD}" || code=$?
  echo "bootstrap with a wrong password: exit ${code}"
  [[ "${code}" == 3 ]]
  entware_probe
  entware_bootstrap "${ENTWARE_PASSWORD}" | tee "${WORK}/ssh-bootstrap.json"
  jq -e '.enrolled' "${WORK}/ssh-bootstrap.json" >/dev/null
  entware entware packages list | tee "${WORK}/ssh-packages.json"
  jq -e '[.packages[].name] | index("opkg")' "${WORK}/ssh-packages.json" >/dev/null
  entware entware packages install mc | tee "${WORK}/ssh-install.json"
  jq -e '.package == "mc" and .before == null and .after != null' "${WORK}/ssh-install.json" >/dev/null
  entware entware services restart S80nginx | tee "${WORK}/ssh-restart.json"
  jq -e '.service == "S80nginx" and .state == "running"' "${WORK}/ssh-restart.json" >/dev/null
  entware entware ssh revoke | tee "${WORK}/ssh-revoke.json"
  jq -e '.revoked' "${WORK}/ssh-revoke.json" >/dev/null
  # Revoked: kcc no longer holds an enrolment for the router (exit 10, nothing sent).
  code=0
  entware entware packages list || code=$?
  echo "packages list after the revoke: exit ${code}"
  [[ "${code}" == 10 ]]
}

# ---------------------------------------------------------------- MCP legs
DEDICATED="https://localhost:${MCP_PORT}/mcp"
OAUTH_REDIRECT="http://127.0.0.1:9/callback"

# The CSRF token of the page at path $1, read with the cookie jar $2.
page_csrf() {
  local html
  html="$(curl_tls -c "$2" -b "$2" "${BASE}$1")"
  sed -n 's/.*<meta name="csrf-token" content="\([^"]*\)".*/\1/p' <<<"${html}" | head -n 1
}

# Signs the e2e user in with the cookie jar $1.
web_sign_in() {
  local csrf code
  csrf="$(page_csrf /ui/login "$1")"
  [[ -n "${csrf}" ]]
  code="$(curl_tls -c "$1" -b "$1" -o /dev/null -w '%{http_code}' \
    -H "Origin: ${BASE}" -H 'sec-fetch-site: same-origin' -H "x-csrf-token: ${csrf}" \
    --data-urlencode username=e2e --data-urlencode "password@${WORK}/etc/e2e-user.password" \
    "${BASE}/ui/login")"
  echo "sign-in: ${code}"
  [[ "${code}" == 303 ]]
}

# A same-origin htmx POST to path $2 with the cookie jar $1; curl options after them.
web_post() {
  local jar="$1" path="$2" csrf
  shift 2
  csrf="$(page_csrf /ui/admin/mcp "${jar}")"
  [[ -n "${csrf}" ]]
  curl_tls -c "${jar}" -b "${jar}" -H "Origin: ${BASE}" -H 'sec-fetch-site: same-origin' \
    -H "x-csrf-token: ${csrf}" -H 'hx-request: true' "$@" "${BASE}${path}"
}

# Saves the MCP settings `key=value` pairs after the jar $1 on the MCP page, with the
# password re-entry a sign-in change needs, and waits for the listener restart to be
# applied. The status fragment's own deadline bounds the wait: server.shutdown_timeout
# + 10 s after the save.
mcp_settle() {
  local jar="$1" pair args=() code until html
  shift
  for pair in "$@"; do
    args+=(--data-urlencode "field=${pair%%=*}" --data-urlencode "${pair}")
  done
  code="$(web_post "${jar}" /ui/admin/mcp -o "${WORK}/mcp-save.html" -w '%{http_code}' \
    "${args[@]}" --data-urlencode "password@${WORK}/etc/e2e-user.password")"
  echo "save $*: ${code}"
  until="$(sed -n 's|.*hx-get="/ui/admin/mcp/status?until=\([0-9]*\)".*|\1|p' "${WORK}/mcp-save.html" | head -n 1)"
  if [[ "${code}" != 200 || -z "${until}" ]]; then
    cat "${WORK}/mcp-save.html"
    return 1
  fi
  while (($(date +%s) <= until + 1)); do
    html="$(curl_tls -b "${jar}" "${BASE}/ui/admin/mcp/status?until=${until}" || true)"
    if grep -q 'data-message-key="web-admin-mcp-restart-applied"' <<<"${html}"; then
      echo "restart applied"
      return 0
    fi
    if grep -q 'data-message-key=' <<<"${html}"; then
      echo "${html}"
      return 1
    fi
    sleep 0.5
  done
  echo "the restart was not applied by its deadline ${until}"
  return 1
}

# The JSON-RPC message of an MCP reply on stdin: the body, or the last `data:` line of an
# event stream.
rpc_message() {
  local body data
  body="$(cat)"
  data="$(sed -n 's/^data:[[:space:]]*//p' <<<"${body}" | sed '/^[[:space:]]*$/d' | tail -n 1)"
  printf '%s\n' "${data:-${body}}"
}

# POSTs the JSON-RPC text $2 to the MCP endpoint $1 in the session MCP_SESSION (when one
# is open); curl options after them. The headers go to ${WORK}/mcp.headers.
mcp_post() {
  local url="$1" body="$2"
  shift 2
  curl -sS --max-time 20 -D "${WORK}/mcp.headers" "$@" \
    -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
    ${MCP_SESSION:+-H "Mcp-Session-Id: ${MCP_SESSION}"} --data "${body}" "${url}"
}

MCP_INITIALIZE='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}'

# Opens an MCP session at $1 with the curl options after it: sets MCP_SESSION.
mcp_open() {
  local url="$1"
  shift
  MCP_SESSION=""
  mcp_post "${url}" "${MCP_INITIALIZE}" "$@" >/dev/null
  MCP_SESSION="$(sed -n 's/^mcp-session-id: *\([^[:space:]]*\).*/\1/Ip' "${WORK}/mcp.headers")"
  [[ -n "${MCP_SESSION}" ]]
  mcp_post "${url}" '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$@" >/dev/null
}

# The JSON-RPC answer to tools/list at $1 in the open session; curl options after it.
mcp_tools() {
  local url="$1"
  shift
  mcp_post "${url}" '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' "$@" | rpc_message
}

# Downloads the dedicated listener's self-signed certificate from the MCP page (jar $1),
# waiting for the listener to have generated it.
dedicated_cert() {
  local code tries
  for ((tries = 60; tries > 0; tries--)); do
    code="$(curl_tls -b "$1" -o "${WORK}/dedicated-cert.pem" -w '%{http_code}' \
      "${BASE}/ui/admin/mcp/certificate")"
    [[ "${code}" == 200 ]] && break
    sleep 0.5
  done
  echo "dedicated certificate: ${code}"
  [[ "${code}" == 200 ]]
  for ((tries = 60; tries > 0; tries--)); do
    curl -sS --max-time 5 --cacert "${WORK}/dedicated-cert.pem" -o /dev/null "${DEDICATED}" && return 0
    sleep 0.5
  done
  return 1
}

mcp_dedicated() {
  local jar="${WORK}/jar-dedicated" key code
  web_sign_in "${jar}"
  dedicated_cert "${jar}"
  code="$(curl -sS --max-time 20 --cacert "${WORK}/dedicated-cert.pem" -o /dev/null -w '%{http_code}' \
    -H 'Authorization: Bearer kcc-e2e-not-a-key' -H 'Accept: application/json, text/event-stream' \
    -H 'Content-Type: application/json' --data "${MCP_INITIALIZE}" "${DEDICATED}")"
  echo "unknown API key: ${code}"
  [[ "${code}" == 401 ]]
  key="$(jq -r '.key' "${WORK}/apikey.json")"
  mcp_open "${DEDICATED}" --cacert "${WORK}/dedicated-cert.pem" -H "Authorization: Bearer ${key}"
  mcp_tools "${DEDICATED}" --cacert "${WORK}/dedicated-cert.pem" -H "Authorization: Bearer ${key}" \
    | tee "${WORK}/dedicated-tools.json"
  jq -e '[.result.tools[].name] | index("kcc_router_info")' "${WORK}/dedicated-tools.json" >/dev/null
}

mcp_mtls() {
  local jar="${WORK}/jar-mtls" dir="${WORK}/mtls" code
  mkdir -p "${dir}"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj /CN=kcc-e2e-client-ca -addext basicConstraints=critical,CA:TRUE \
    -addext keyUsage=critical,keyCertSign,cRLSign -keyout "${dir}/ca.key" -out "${dir}/ca.pem"
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=kcc-e2e-client \
    -keyout "${dir}/client.key" -out "${dir}/client.csr"
  printf '%s\n' basicConstraints=critical,CA:FALSE keyUsage=critical,digitalSignature \
    extendedKeyUsage=clientAuth >"${dir}/client.ext"
  openssl x509 -req -in "${dir}/client.csr" -CA "${dir}/ca.pem" -CAkey "${dir}/ca.key" \
    -set_serial 2 -days 2 -extfile "${dir}/client.ext" -out "${dir}/client.pem"
  web_sign_in "${jar}"
  dedicated_cert "${jar}"
  code="$(web_post "${jar}" /ui/admin/mcp/ca -o "${WORK}/mtls-upload.html" -w '%{http_code}' \
    -F kind=mtls -F "file=@${dir}/ca.pem;type=application/x-pem-file")"
  echo "client CA upload: ${code}"
  [[ "${code}" == 200 ]]
  grep -q 'web-admin-mcp-ca-saved' "${WORK}/mtls-upload.html"
  mcp_settle "${jar}" auth.dedicated.mtls=required
  code="$(curl -sS --max-time 20 --cacert "${WORK}/dedicated-cert.pem" -o /dev/null -w '%{http_code}' \
    -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
    --data "${MCP_INITIALIZE}" "${DEDICATED}" || true)"
  echo "initialize without a client certificate: ${code}"
  [[ "${code}" != 200 ]]
  mcp_open "${DEDICATED}" --cacert "${WORK}/dedicated-cert.pem" \
    --cert "${dir}/client.pem" --key "${dir}/client.key"
  mcp_tools "${DEDICATED}" --cacert "${WORK}/dedicated-cert.pem" \
    --cert "${dir}/client.pem" --key "${dir}/client.key" | tee "${WORK}/mtls-tools.json"
  jq -e '.result.tools | length > 0' "${WORK}/mtls-tools.json" >/dev/null
}

mcp_main_restart() {
  local jar="${WORK}/jar-restart" code
  web_sign_in "${jar}"
  mcp_settle "${jar}" auth.main.oauth=kcc
  healthz
  code="$(curl_tls -b "${jar}" -o /dev/null -w '%{http_code}' "${BASE}/ui/r/fake-a")"
  echo "dashboard after the restart: ${code}"
  [[ "${code}" == 200 ]]
  code="$(curl -sS --max-time 10 -o "${WORK}/metrics-restart.prom" -w '%{http_code}' \
    "http://127.0.0.1:${METRICS_PORT}/metrics")"
  echo "metrics after the restart: ${code}"
  [[ "${code}" == 200 ]]
  grep -q '^keenetic_up{' "${WORK}/metrics-restart.prom"
}

# The value of the query parameter $1 in the URL $2.
query_param() {
  sed -n "s/.*[?&]$1=\([^&#]*\).*/\1/p" <<<"$2" | head -n 1
}

mcp_oauth() {
  local jar="${WORK}/jar-oauth" meta code verifier challenge state answer url id html csrf \
    target auth_code token grant
  # The protected resource names the main listener's issuer, which describes itself.
  curl_tls "${BASE}/.well-known/oauth-protected-resource/mcp" | tee "${WORK}/oauth-prm.json"
  jq -e --arg issuer "${BASE}" '.authorization_servers | index($issuer)' "${WORK}/oauth-prm.json" >/dev/null
  meta="${WORK}/oauth-as.json"
  curl_tls "${BASE}/.well-known/oauth-authorization-server" | tee "${meta}"
  jq -e --arg issuer "${BASE}" '.issuer == $issuer and (.code_challenge_methods_supported | index("S256"))' \
    "${meta}" >/dev/null
  code="$(curl_tls -o "${WORK}/oauth-client.json" -w '%{http_code}' -H 'Content-Type: application/json' \
    --data "{\"client_name\":\"kcc e2e\",\"redirect_uris\":[\"${OAUTH_REDIRECT}\"],\"token_endpoint_auth_method\":\"none\",\"grant_types\":[\"authorization_code\",\"refresh_token\"],\"response_types\":[\"code\"]}" \
    "$(jq -r '.registration_endpoint' "${meta}")")"
  echo "registration: ${code}"
  [[ "${code}" == 201 ]]
  verifier="$(openssl rand -hex 32)"
  challenge="$(printf '%s' "${verifier}" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')"
  state="$(openssl rand -hex 16)"
  answer="$(curl_tls -o /dev/null -w '%{http_code} %{redirect_url}' -G \
    --data-urlencode response_type=code \
    --data-urlencode "client_id=$(jq -r '.client_id' "${WORK}/oauth-client.json")" \
    --data-urlencode "redirect_uri=${OAUTH_REDIRECT}" --data-urlencode "code_challenge=${challenge}" \
    --data-urlencode code_challenge_method=S256 --data-urlencode "state=${state}" \
    --data-urlencode "resource=${BASE}/mcp" --data-urlencode scope=mcp \
    "$(jq -r '.authorization_endpoint' "${meta}")")"
  echo "authorize: ${answer%%\?*}"
  [[ "${answer}" == "303 ${BASE}/ui/oauth/consent?request="* ]]
  url="${answer#303 }"
  id="$(query_param request "${url}")"
  # The browser: the consent page without a session is the login carrying the request.
  html="$(curl_tls -c "${jar}" -b "${jar}" "${url}")"
  [[ "$(sed -n 's/.*name="consent" value="\([^"]*\)".*/\1/p' <<<"${html}" | head -n 1)" == "${id}" ]]
  csrf="$(sed -n 's/.*<meta name="csrf-token" content="\([^"]*\)".*/\1/p' <<<"${html}" | head -n 1)"
  answer="$(curl_tls -c "${jar}" -b "${jar}" -o /dev/null -w '%{http_code} %{redirect_url}' \
    -H "Origin: ${BASE}" -H 'sec-fetch-site: same-origin' -H "x-csrf-token: ${csrf}" \
    --data-urlencode username=e2e --data-urlencode "password@${WORK}/etc/e2e-user.password" \
    --data-urlencode "consent=${id}" "${BASE}/ui/login")"
  echo "login with the request: ${answer%%\?*}"
  [[ "${answer}" == "303 ${url}" ]]
  csrf="$(page_csrf "${url#"${BASE}"}" "${jar}")"
  [[ -n "${csrf}" ]]
  code="$(curl_tls -c "${jar}" -b "${jar}" -D "${WORK}/oauth-consent.headers" -o /dev/null \
    -w '%{http_code}' -H "Origin: ${BASE}" -H 'sec-fetch-site: same-origin' \
    -H "x-csrf-token: ${csrf}" -H 'hx-request: true' --data-urlencode "request=${id}" \
    "${BASE}/ui/oauth/consent/approve")"
  target="$(sed -n 's/^hx-redirect: *//Ip' "${WORK}/oauth-consent.headers" | tr -d '\r')"
  echo "approve: ${code}, back to ${target%%\?*}"
  [[ "${target}" == "${OAUTH_REDIRECT}?"* && "$(query_param state "${target}")" == "${state}" ]]
  auth_code="$(query_param code "${target}")"
  [[ -n "${auth_code}" ]]
  curl_tls -o "${WORK}/oauth-token.json" --data-urlencode grant_type=authorization_code \
    --data-urlencode "code=${auth_code}" --data-urlencode "redirect_uri=${OAUTH_REDIRECT}" \
    --data-urlencode "client_id=$(jq -r '.client_id' "${WORK}/oauth-client.json")" \
    --data-urlencode "code_verifier=${verifier}" --data-urlencode "resource=${BASE}/mcp" \
    "$(jq -r '.token_endpoint' "${meta}")"
  jq -e '.token_type == "Bearer" and .access_token and .scope == "mcp"' "${WORK}/oauth-token.json" >/dev/null
  token="$(jq -r '.access_token' "${WORK}/oauth-token.json")"
  mcp_open "${BASE}/mcp" --cacert "${CERT}" -H "Authorization: Bearer ${token}"
  mcp_tools "${BASE}/mcp" --cacert "${CERT}" -H "Authorization: Bearer ${token}" \
    | tee "${WORK}/oauth-tools.json"
  jq -e '[.result.tools[].name] | index("kcc_router_info")' "${WORK}/oauth-tools.json" >/dev/null
  # Revoked with the CLI, the connection's next call is refused.
  kcc --json mcp connections list | tee "${WORK}/oauth-connections.json"
  grant="$(jq -r '[.connections[] | select(.account == "e2e")] | if length == 1 then .[0].grant else empty end' \
    "${WORK}/oauth-connections.json")"
  [[ -n "${grant}" ]]
  kcc --json --confirm-destructive "${grant}" mcp connections revoke "${grant}"
  mcp_tools "${BASE}/mcp" --cacert "${CERT}" -H "Authorization: Bearer ${token}" \
    | tee "${WORK}/oauth-revoked.json"
  jq -e '.result == null and .error.message == "forbidden"' "${WORK}/oauth-revoked.json" >/dev/null
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
step telegram-test-message telegram_test_message
step schedule-run-now schedule_run_now
step mcp-http mcp_http
step entware-ssh entware_ssh
step mcp-dedicated mcp_dedicated
step mcp-mtls mcp_mtls
step mcp-main-restart mcp_main_restart
step mcp-oauth mcp_oauth
step healthcheck healthcheck
step sighup-reload sighup_reload
step graceful-sigterm graceful_sigterm
step no-denials denials
if ((FAILED > 0)); then
  echo "e2e: ${FAILED} step(s) failed"
  exit 1
fi
echo "e2e: all steps passed (${MODE})"
