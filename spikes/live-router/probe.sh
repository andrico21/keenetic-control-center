#!/usr/bin/env bash
# Live-router behaviour probes (plan todo 53).
#
# Verifies, against a real Keenetic/Netcraze *test* router, the RCI behaviours
# that the fake router (todo 16) and the migration rules/applier (todos 28, 30)
# depend on. See RESULT.md next to this file for the outcome of the last run.
#
# Requirements: bash >= 4, curl, jq, openssl, coreutils (od, mktemp, date).
#
# Gating (every gate is a hard early exit that logs `live-skip:<reason>`):
#   1. KCC_LIVE_URL, KCC_LIVE_LOGIN, KCC_LIVE_PASSWORD_FILE set, KCC_LIVE_ALLOW_WRITE=1
#   2. KCC_LIVE_ALLOW_SERIAL set and non-empty; KCC_LIVE_URL is http(s)://host[:port]
#   3. ndw2 login + GET `show identification`; the serial must be listed in
#      KCC_LIVE_ALLOW_SERIAL (comma-separated) before any RCI POST is sent.
# Probe 8 (may reboot the router) additionally needs KCC_LIVE_ALLOW_REBOOT=1.
#
# Evidence: KCC_PROBE_EVIDENCE (default .omo/evidence/task-53-keenetic-control-center.json).
# Secrets (login password, probe passwords, ns3 blobs, hashes, challenges) are
# redacted before anything is written to the evidence file.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
EVIDENCE="${KCC_PROBE_EVIDENCE:-${REPO_ROOT}/.omo/evidence/task-53-keenetic-control-center.json}"
readonly SCRIPT_DIR REPO_ROOT EVIDENCE

readonly TEST_IFACE="PPTP9"
readonly TEST_USER="kccprobe"
readonly NS3_PLAINTEXT="kccprobe1"
readonly PROBE_DESC="kcc-probe"

BASE_URL=""
LOGIN=""
PASSWORD=""
REALM=""
WORK_DIR=""
COOKIE_JAR=""
SECRETS=()

# Cleanup state: set before the mutating request so a failure mid-request still
# triggers the matching undo.
CREATED_IFACE=0
CREATED_USER=0
DESC_CHANGED=0
ORIG_DESC_LINE=""
FAILSAFE_ARMED=0
NEED_SAVE=0
LOG_STREAM=0
AUTHENTICATED=0
EV_READY=0
LOGIN_ERR=""

# Last response.
RESP_STATUS=""
RESP_BODY=""
RESP_HEADERS=""

log() { printf 'probe53: %s\n' "$*"; }

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ---------------------------------------------------------------------------
# Evidence file helpers
# ---------------------------------------------------------------------------

ev_init() {
  mkdir -p -- "$(dirname -- "${EVIDENCE}")"
  jq -n --arg started "$(now)" \
    '{task: 53, started: $started, requests: [], probes: {}}' >"${EVIDENCE}"
  EV_READY=1
}

# ev_update <jq filter> [jq args...]: rewrite the evidence file in place.
ev_update() {
  local filter="$1"
  shift
  local tmp="${EVIDENCE}.tmp"
  jq "$@" "${filter}" "${EVIDENCE}" >"${tmp}"
  mv -- "${tmp}" "${EVIDENCE}"
}

# ev_set <probe> <key> <json value>
ev_set() {
  ev_update ".probes[\$p][\$k] = \$v" --arg p "$1" --arg k "$2" --argjson v "$3"
}

# live_skip <reason>: record and exit successfully (a skip is never silent).
live_skip() {
  log "live-skip:$1"
  if ((EV_READY)); then
    ev_update ". + {\"live-skip\": \$r, finished: \$f}" --arg r "$1" --arg f "$(now)"
  else
    mkdir -p -- "$(dirname -- "${EVIDENCE}")"
    jq -n --arg r "$1" --arg f "$(now)" '{task: 53, "live-skip": $r, finished: $f}' >"${EVIDENCE}"
  fi
  exit 0
}

# redact <text>: strip every known secret and every password/challenge token.
redact() {
  local s="$1" secret
  for secret in "${SECRETS[@]}"; do
    [[ -n "${secret}" ]] && s="${s//"${secret}"/<redacted>}"
  done
  printf '%s' "${s}" | sed -E \
    -e 's/(password[[:space:]]+(md5|nt|plain|ns3|sha256|sha512|hash))[[:space:]]+[^[:space:]"]+/\1 <redacted>/g' \
    -e 's/((challenge|session_id)=")[^"]*/\1<redacted>/g' \
    -e 's/(X-NDM-Challenge:[[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/((psk|key|secret|pre-shared-key)[[:space:]]+)[^[:space:]"]+/\1<redacted>/g'
}

# as_json <text>: the text as JSON if it parses, else as a JSON string.
as_json() {
  if jq -e . >/dev/null 2>&1 <<<"$1"; then
    jq -c . <<<"$1"
  else
    jq -Rs . <<<"$1"
  fi
}

# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

# http <method> <path> [json body]: sets RESP_STATUS, RESP_BODY, RESP_HEADERS
# and appends the method/path/status to the evidence request log.
http() {
  local method="$1" path="$2" body="${3-}"
  local hdr="${WORK_DIR}/headers" out="${WORK_DIR}/body"
  local args=(-sS -o "${out}" -D "${hdr}" -w '%{http_code}'
    --connect-timeout 5 --max-time 30
    -b "${COOKIE_JAR}" -c "${COOKIE_JAR}" -X "${method}")
  if [[ -n "${body}" ]]; then
    args+=(-H 'Content-Type: application/json' --data-binary @-)
  fi
  : >"${hdr}"
  : >"${out}"
  if [[ -n "${body}" ]]; then
    RESP_STATUS="$(printf '%s' "${body}" | curl "${args[@]}" "${BASE_URL}${path}")" || RESP_STATUS="000"
  else
    RESP_STATUS="$(curl "${args[@]}" "${BASE_URL}${path}")" || RESP_STATUS="000"
  fi
  RESP_HEADERS="$(tr -d '\r' <"${hdr}")"
  RESP_BODY="$(cat -- "${out}")"
  ev_update ".requests += [{at: \$at, method: \$m, path: \$p, status: \$s}]" \
    --arg at "$(now)" --arg m "${method}" --arg p "${path}" --arg s "${RESP_STATUS}"
}

# record <probe> <step> [summary jq filter]: append the last request/response
# (redacted) to the probe's step list. With a filter, the JSON body is replaced
# by the filter's output (used to record shapes rather than log contents).
record() {
  local probe="$1" step="$2" filter="${3-}" body_json
  if [[ -n "${filter}" ]] && jq -e . >/dev/null 2>&1 <<<"${RESP_BODY}"; then
    body_json="$(jq -c "${filter}" <<<"${RESP_BODY}" 2>/dev/null)" || body_json='"<shape filter failed>"'
  else
    body_json="$(as_json "$(redact "${RESP_BODY}")")"
  fi
  ev_update ".probes[\$p].steps += [{step: \$st, status: \$s, body: \$b}]" \
    --arg p "${probe}" --arg st "${step}" --arg s "${RESP_STATUS}" --argjson b "${body_json}"
}

# rci_parse <cli line>: POST /rci/ {"parse": line}. Returns 1 when the HTTP
# status is not 200 or the parse result carries a status of type "error".
rci_parse() {
  local body
  body="$(jq -nc --arg l "$1" '{parse: $l}')"
  http POST /rci/ "${body}"
  [[ "${RESP_STATUS}" == "200" ]] || return 1
  ! jq -e '[.. | objects | select(.status? == "error")] | length > 0' >/dev/null 2>&1 <<<"${RESP_BODY}"
}

# Record a parse request with the CLI line redacted.
record_parse() {
  local probe="$1" step="$2" line="$3"
  ev_update ".probes[\$p].steps += [{step: \$st, request: {method: \"POST\", path: \"/rci/\", parse: \$l}}]" \
    --arg p "${probe}" --arg st "${step}" --arg l "$(redact "${line}")"
  record "${probe}" "${step}"
}

running_config() {
  http GET /ci/running-config.txt
  [[ "${RESP_STATUS}" == "200" ]]
}

# config_block <text> <header line>: the lines of a top-level block, header
# included, up to the closing "!".
config_block() {
  awk -v h="$2" '
    $0 == h { inside = 1; print; next }
    inside && /^!/ { exit }
    inside { print }
  ' <<<"$1"
}

hex_md5() { openssl dgst -md5 -r | cut -d' ' -f1; }
hex_sha256() { openssl dgst -sha256 -r | cut -d' ' -f1; }

# ---------------------------------------------------------------------------
# ns3 codec (port of zyxel_scramble.py by Felis-Sapiens, R-NS3)
# ---------------------------------------------------------------------------

NS3=()

ns3_first_step() {
  local x1=$(($1 & 255)) x2=$(($2 & 255)) i t
  for ((i = 0; i < ${#NS3[@]}; i++)); do
    NS3[i]=$(((NS3[i] ^ x2) & 255))
    t=$(((x1 + x2) & 255))
    x1=${x2}
    x2=${t}
  done
}

ns3_second_step() {
  local x=0 a i b
  for b in "${NS3[@]}"; do x=$((x ^ b)); done
  for ((i = 1; i < 8; i++)); do
    a=$((((x >> i) ^ (~x << i)) & 255))
    x=$((((a << i) ^ (~a ^ x)) & 255))
  done
  for ((i = 0; i < ${#NS3[@]}; i++)); do NS3[i]=$((NS3[i] ^ x)); done
}

ns3_encode() {
  local plain="$1" old_len length i x1 x2 pos
  local -a md5 bytes
  old_len=${#plain}
  length=$((old_len + 3))
  if ((length < 0x13)); then
    length=0x12
  elif ((length < 0x25)); then
    length=0x24
  elif ((length < 0x49)); then
    length=0x48
  else
    return 1
  fi
  length=$((length))
  read -r -a md5 <<<"$(printf '%s' "${plain}" | openssl dgst -md5 -binary | od -An -v -tu1 | tr -s ' \n' ' ')"
  read -r -a bytes <<<"$(printf '%s' "${plain}" | od -An -v -tu1 | tr -s ' \n' ' ')"
  NS3=("${bytes[@]}")
  if ((length != old_len)); then
    NS3+=(0)
    for ((i = old_len + 1; i < length - 2; i++)); do
      NS3+=($(((NS3[i - old_len - 1] * 2 + md5[2 + i % 14]) & 255)))
    done
  fi
  x1=${md5[0]}
  x2=${md5[1]}
  ns3_first_step "${x1}" "${x2}"
  ns3_second_step
  pos=$((x2 % (length - 1)))
  NS3=("${NS3[@]:0:pos}" "${x1}" "${NS3[@]:pos}")
  pos=$((length / 7))
  NS3=("${NS3[@]:0:pos}" "${x2}" "${NS3[@]:pos}")
  bytes_to_b64 "${NS3[@]}"
}

bytes_to_b64() {
  local esc="" b
  for b in "$@"; do esc+="$(printf '\\0%03o' "${b}")"; done
  printf '%b' "${esc}" | openssl base64 -A
}

ns3_decode() {
  local blob="$1" length a1 a2 x1 x2 i out=""
  while ((${#blob} % 4 != 0)); do blob+="="; done
  read -r -a NS3 <<<"$(printf '%s' "${blob}" | openssl base64 -d -A | od -An -v -tu1 | tr -s ' \n' ' ')"
  length=${#NS3[@]}
  case "${length}" in 18 | 36 | 72) ;; *) return 1 ;; esac
  a2=$((length / 7))
  x2=${NS3[a2]}
  NS3=("${NS3[@]:0:a2}" "${NS3[@]:a2+1}")
  a1=$((x2 % (length - 1)))
  x1=${NS3[a1]}
  NS3=("${NS3[@]:0:a1}" "${NS3[@]:a1+1}")
  ns3_second_step
  ns3_first_step "${x1}" "${x2}"
  for ((i = 0; i < ${#NS3[@]}; i++)); do
    ((NS3[i] == 0)) && break
    out+="$(printf '%b' "$(printf '\\0%03o' "${NS3[i]}")")"
  done
  printf '%s' "${out}"
}

# ---------------------------------------------------------------------------
# Cleanup (always runs; never leaves probe objects on the router)
# ---------------------------------------------------------------------------

cleanup() {
  local rc=$?
  set +e
  if ((AUTHENTICATED)); then
    if ((LOG_STREAM)); then
      http DELETE /rci/show/log
      LOG_STREAM=0
    fi
    if ((FAILSAFE_ARMED)); then
      rci_parse "no system configuration fail-safe timer" && FAILSAFE_ARMED=0
    fi
    if ((CREATED_IFACE)); then
      rci_parse "no interface ${TEST_IFACE}" && CREATED_IFACE=0
    fi
    if ((CREATED_USER)); then
      rci_parse "no user ${TEST_USER}" && CREATED_USER=0
    fi
    if ((DESC_CHANGED)); then
      restore_description && DESC_CHANGED=0
    fi
    if ((NEED_SAVE)); then
      rci_parse "system configuration save" && NEED_SAVE=0
    fi
    if ((EV_READY)); then
      ev_update ".cleanup = {iface_left: \$i, user_left: \$u, desc_left: \$d, failsafe_left: \$f, unsaved_restore: \$s}" \
        --argjson i "${CREATED_IFACE}" --argjson u "${CREATED_USER}" --argjson d "${DESC_CHANGED}" \
        --argjson f "${FAILSAFE_ARMED}" --argjson s "${NEED_SAVE}"
    fi
  fi
  if ((EV_READY)); then
    ev_update ".finished = \$f | .exit_code = \$c" --arg f "$(now)" --argjson c "${rc}"
  fi
  [[ -n "${WORK_DIR}" ]] && rm -rf -- "${WORK_DIR}"
  if ((CREATED_IFACE || CREATED_USER || DESC_CHANGED || FAILSAFE_ARMED)); then
    log "CLEANUP INCOMPLETE: iface=${CREATED_IFACE} user=${CREATED_USER} desc=${DESC_CHANGED} failsafe=${FAILSAFE_ARMED}" >&2
  fi
  exit "${rc}"
}

restore_description() {
  if [[ -n "${ORIG_DESC_LINE}" ]]; then
    rci_parse "system ${ORIG_DESC_LINE}"
  else
    rci_parse "no system description"
  fi
}

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

gate_env() {
  local v
  for v in KCC_LIVE_URL KCC_LIVE_LOGIN KCC_LIVE_PASSWORD_FILE; do
    [[ -n "${!v-}" ]] || live_skip "${v,,}-unset"
  done
  [[ "${KCC_LIVE_ALLOW_WRITE-}" == "1" ]] || live_skip "kcc_live_allow_write-not-1"
  [[ -n "${KCC_LIVE_ALLOW_SERIAL-}" ]] || live_skip "kcc_live_allow_serial-unset"
  local url_re='^https?://[][A-Za-z0-9.:-]+/?$'
  [[ "${KCC_LIVE_URL}" =~ ${url_re} ]] || live_skip "kcc_live_url-invalid"
  [[ -r "${KCC_LIVE_PASSWORD_FILE}" ]] || live_skip "kcc_live_password_file-unreadable"
  local bin
  for bin in curl jq openssl od; do
    command -v "${bin}" >/dev/null 2>&1 || live_skip "missing-tool-${bin}"
  done
  BASE_URL="${KCC_LIVE_URL%/}"
  LOGIN="${KCC_LIVE_LOGIN}"
  IFS= read -r PASSWORD <"${KCC_LIVE_PASSWORD_FILE}" || true
  [[ -n "${PASSWORD}" ]] || live_skip "kcc_live_password_file-empty"
  SECRETS+=("${PASSWORD}")
}

# ndw2 login, adapted from R-RCI docs/ndw2_auth_fn.sh:
# hash = sha256hex(challenge || md5hex(login ":" realm ":" password)).
# Also records probe 1 (the /auth headers). Returns 1 with LOGIN_ERR set on failure.
login() {
  local record_probe="${1-}" challenge www hash body set_cookie
  http GET /auth
  [[ "${RESP_STATUS}" != "000" ]] || { LOGIN_ERR="router-unreachable"; return 1; }
  www="$(grep -i '^WWW-Authenticate:' <<<"${RESP_HEADERS}" | cut -d' ' -f2- || true)"
  REALM="$(grep -i '^X-NDM-Realm:' <<<"${RESP_HEADERS}" | cut -d' ' -f2- || true)"
  challenge="$(grep -i '^X-NDM-Challenge:' <<<"${RESP_HEADERS}" | cut -d' ' -f2- || true)"
  set_cookie="$(grep -i '^Set-Cookie:' <<<"${RESP_HEADERS}" | head -n1 | cut -d' ' -f2- || true)"
  [[ -n "${challenge}" ]] && SECRETS+=("${challenge}")

  if [[ -n "${record_probe}" ]]; then
    ev_set p1_auth_headers result "$(jq -nc \
      --arg status "${RESP_STATUS}" \
      --arg www "$(redact "${www}")" \
      --arg realm "${REALM}" \
      --arg cookie_name "${set_cookie%%=*}" \
      --arg max_age "$(grep -oiE 'Max-Age=[0-9]+' <<<"${set_cookie}" | cut -d= -f2 || true)" \
      --arg cookie_attrs "$(sed -E 's/^[^=]+=[^;]*;?//' <<<"${set_cookie}")" \
      '{status: $status,
        schemes: ($www | [scan("x-ndw[0-9]+-interactive")] | unique),
        www_authenticate: $www,
        realm: $realm,
        cookie_name: $cookie_name,
        max_age: (if $max_age == "" then null else ($max_age | tonumber) end),
        cookie_attributes: $cookie_attrs}')"
  fi

  if [[ "${RESP_STATUS}" == "200" ]]; then
    AUTHENTICATED=1
    return 0
  fi
  [[ "${RESP_STATUS}" == "401" ]] || { LOGIN_ERR="auth-unexpected-status-${RESP_STATUS}"; return 1; }
  grep -q 'x-ndw2-interactive' <<<"${www}" || [[ -z "${www}" && -n "${challenge}" ]] ||
    { LOGIN_ERR="ndw2-not-advertised"; return 1; }
  [[ -n "${challenge}" && -n "${REALM}" ]] || { LOGIN_ERR="ndw2-challenge-missing"; return 1; }

  hash="$(printf '%s%s' "${challenge}" \
    "$(printf '%s:%s:%s' "${LOGIN}" "${REALM}" "${PASSWORD}" | hex_md5)" | hex_sha256)"
  SECRETS+=("${hash}")
  body="$(jq -nc --arg l "${LOGIN}" --arg p "${hash}" '{login: $l, password: $p}')"
  http POST /auth "${body}"
  [[ "${RESP_STATUS}" == "200" ]] || { LOGIN_ERR="auth-failed-status-${RESP_STATUS}"; return 1; }
  AUTHENTICATED=1
}

gate_serial() {
  local serial allowed entry
  http GET /rci/show/identification
  [[ "${RESP_STATUS}" == "200" ]] || live_skip "identification-status-${RESP_STATUS}"
  serial="$(jq -r '.serial // empty' <<<"${RESP_BODY}" 2>/dev/null || true)"
  [[ -n "${serial}" ]] || live_skip "identification-no-serial"
  allowed=0
  IFS=',' read -r -a entries <<<"${KCC_LIVE_ALLOW_SERIAL}"
  for entry in "${entries[@]}"; do
    entry="${entry//[[:space:]]/}"
    [[ -n "${entry}" && "${entry}" == "${serial}" ]] && allowed=1
  done
  ev_update ".serial_check = {serial: \$s, allowed: (\$a == \"1\")}" --arg s "${serial}" --arg a "${allowed}"
  # Not authorised to touch this router: forget the session so cleanup sends nothing.
  ((allowed)) || {
    AUTHENTICATED=0
    live_skip "serial-not-allowed"
  }
}

# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

probe2_identity() {
  local p=p2_identity path
  for path in /rci/show/version /rci/show/system/mode /rci/show/identification; do
    http GET "${path}"
    record "${p}" "GET ${path}"
  done
}

iface_absent() {
  running_config || return 1
  [[ -z "$(config_block "${RESP_BODY}" "interface ${TEST_IFACE}")" ]]
}

probe3_parse() {
  local p=p3_full_path_parse line block accepted present removed
  if ! iface_absent; then
    ev_set "${p}" result '{"skipped": "test interface already exists or running-config unreadable"}'
    return 0
  fi
  line="interface ${TEST_IFACE} description \"${PROBE_DESC}\""
  CREATED_IFACE=1
  accepted=false
  rci_parse "${line}" && accepted=true
  record_parse "${p}" "parse full path" "${line}"
  running_config || true
  block="$(config_block "${RESP_BODY}" "interface ${TEST_IFACE}")"
  present=false
  grep -qE "^[[:space:]]+description \"?${PROBE_DESC}\"?$" <<<"${block}" && present=true
  ev_update ".probes[\$p].running_config_block = \$b" --arg p "${p}" --arg b "$(redact "${block}")"
  rci_parse "no interface ${TEST_IFACE}" || true
  record_parse "${p}" "remove" "no interface ${TEST_IFACE}"
  removed=false
  iface_absent && removed=true && CREATED_IFACE=0
  ev_set "${p}" result "$(jq -nc --argjson a "${accepted}" --argjson pr "${present}" --argjson r "${removed}" \
    '{parse_accepted: $a, description_in_running_config: $pr, removed: $r}')"
}

probe4_ns3() {
  local p=p4_ns3_input blob line block stored_kind stored decoded accepted matches same_blob
  if ! iface_absent; then
    ev_set "${p}" result '{"skipped": "test interface already exists or running-config unreadable"}'
    return 0
  fi
  blob="$(ns3_encode "${NS3_PLAINTEXT}")"
  SECRETS+=("${blob}")
  # Self-check of the shell codec before relying on it.
  [[ "$(ns3_decode "${blob}")" == "${NS3_PLAINTEXT}" ]] || {
    ev_set "${p}" result '{"error": "local ns3 codec round-trip failed"}'
    return 0
  }
  CREATED_IFACE=1
  rci_parse "interface ${TEST_IFACE}" || true
  record_parse "${p}" "create" "interface ${TEST_IFACE}"
  line="interface ${TEST_IFACE} authentication password ns3 ${blob}"
  accepted=false
  rci_parse "${line}" && accepted=true
  record_parse "${p}" "parse ns3 password" "${line}"
  running_config || true
  block="$(config_block "${RESP_BODY}" "interface ${TEST_IFACE}")"
  stored_kind="$(sed -nE 's/^[[:space:]]+authentication password ([a-z0-9]+) .*/\1/p' <<<"${block}" | head -n1)"
  stored="$(sed -nE 's/^[[:space:]]+authentication password [a-z0-9]+ "?([^" ]+)"?$/\1/p' <<<"${block}" | head -n1)"
  [[ -n "${stored}" ]] && SECRETS+=("${stored}")
  decoded=""
  [[ "${stored_kind}" == "ns3" && -n "${stored}" ]] && decoded="$(ns3_decode "${stored}" || true)"
  matches=false
  [[ "${decoded}" == "${NS3_PLAINTEXT}" ]] && matches=true
  same_blob=false
  [[ "${stored}" == "${blob}" ]] && same_blob=true
  rci_parse "no interface ${TEST_IFACE}" || true
  record_parse "${p}" "remove" "no interface ${TEST_IFACE}"
  iface_absent && CREATED_IFACE=0
  ev_set "${p}" result "$(jq -nc --argjson a "${accepted}" --arg k "${stored_kind}" \
    --argjson m "${matches}" --argjson s "${same_blob}" --argjson left "${CREATED_IFACE}" \
    '{ns3_input_accepted: $a, stored_kind: $k, decoded_equals_plaintext: $m,
      stored_blob_identical_to_input: $s, removed: ($left == 0)}')"
}

probe5_realm_hash() {
  local p=p5_realm_hash pw line block stored expected matches has_nt has_plain removed
  running_config || true
  if [[ -n "$(config_block "${RESP_BODY}" "user ${TEST_USER}")" ]]; then
    ev_set "${p}" result '{"skipped": "test user already exists"}'
    return 0
  fi
  pw="$(openssl rand -hex 8)"
  SECRETS+=("${pw}")
  line="user ${TEST_USER} password plain ${pw}"
  CREATED_USER=1
  rci_parse "${line}" || true
  record_parse "${p}" "create user" "${line}"
  running_config || true
  block="$(config_block "${RESP_BODY}" "user ${TEST_USER}")"
  stored="$(sed -nE 's/^[[:space:]]+password md5 "?([0-9a-fA-F]+)"?$/\1/p' <<<"${block}" | head -n1)"
  expected="$(printf '%s:%s:%s' "${TEST_USER}" "${REALM}" "${pw}" | hex_md5)"
  SECRETS+=("${expected}")
  [[ -n "${stored}" ]] && SECRETS+=("${stored}")
  matches=false
  [[ -n "${stored}" && "${stored,,}" == "${expected}" ]] && matches=true
  has_nt=false
  grep -qE '^[[:space:]]+password nt ' <<<"${block}" && has_nt=true
  has_plain=false
  grep -qE '^[[:space:]]+password plain ' <<<"${block}" && has_plain=true
  ev_update ".probes[\$p].running_config_block = \$b" --arg p "${p}" --arg b "$(redact "${block}")"
  rci_parse "no user ${TEST_USER}" || true
  record_parse "${p}" "remove user" "no user ${TEST_USER}"
  running_config || true
  removed=false
  [[ -z "$(config_block "${RESP_BODY}" "user ${TEST_USER}")" ]] && removed=true && CREATED_USER=0
  ev_set "${p}" result "$(jq -nc --arg r "${REALM}" --argjson md5 "$([[ -n "${stored}" ]] && echo true || echo false)" \
    --argjson m "${matches}" --argjson nt "${has_nt}" --argjson pl "${has_plain}" --argjson rm "${removed}" \
    '{realm: $r, md5_line_present: $md5, md5_equals_md5hex_user_realm_password: $m,
      nt_line_present: $nt, plain_line_present: $pl, removed: $rm}')"
}

# jq filters that record structure, never log text.
readonly SHAPE_FILTER='{type: type, keys: (if type == "object" then keys else null end)}'
readonly LOG_SHAPE_FILTER='
def logv: if type == "object" then .log else null end;
def entries: logv | if type == "object" then [.[]] elif type == "array" then . else [] end;
{
  top_keys: (if type == "object" then keys else null end),
  continued: (if type == "object" then .continued else null end),
  log_type: (logv | type),
  log_ids: (logv | if type == "object" then keys
                   elif type == "array" then [range(0; length) | tostring]
                   else [] end),
  entry_paths: (entries | (first // {}) | [paths(scalars) | map(tostring) | join(".")]),
  has_timestamp_field: (entries | (first // {}) | [paths | map(tostring) | join(".") | test("time|date"; "i")] | any)
}'

probe6_post_only_shows() {
  local p=p6_show_log_ipsec path i prev_ids ids new_only all_new
  for path in /rci/show/log /rci/show/ipsec; do
    http GET "${path}"
    record "${p}" "GET ${path}" "${SHAPE_FILTER}"
    http POST "${path}" '{}'
    record "${p}" "POST ${path} {}" "${SHAPE_FILTER}"
  done
  http POST /rci/show/log '{"once": true, "max-lines": 20}'
  record "${p}" 'POST /rci/show/log {"once":true,"max-lines":20}' "${LOG_SHAPE_FILTER}"

  LOG_STREAM=1
  http POST /rci/show/log '{"once": false, "max-lines": 5}'
  record "${p}" 'POST /rci/show/log {"once":false,"max-lines":5}' "${LOG_SHAPE_FILTER}"
  prev_ids="$(jq -c "${LOG_SHAPE_FILTER} | .log_ids" <<<"${RESP_BODY}" 2>/dev/null || echo '[]')"
  all_new=true
  for i in 1 2 3; do
    sleep 5
    http GET /rci/show/log
    record "${p}" "GET /rci/show/log poll ${i}" "${LOG_SHAPE_FILTER}"
    ids="$(jq -c "${LOG_SHAPE_FILTER} | .log_ids" <<<"${RESP_BODY}" 2>/dev/null || echo '[]')"
    new_only="$(jq -nc --argjson a "${prev_ids}" --argjson b "${ids}" '($a - ($a - $b)) | length == 0')"
    [[ "${new_only}" == "true" ]] || all_new=false
    prev_ids="$(jq -nc --argjson a "${prev_ids}" --argjson b "${ids}" '$a + $b | unique')"
  done
  http DELETE /rci/show/log
  record "${p}" "DELETE /rci/show/log"
  LOG_STREAM=0
  ev_set "${p}" result "$(jq -nc --argjson n "${all_new}" '{polls_return_only_new_ids: $n}')"
}

# Current "system ... description" line (without the leading "system ").
read_description() {
  running_config || return 1
  local block
  block="$(config_block "${RESP_BODY}" "system")"
  sed -nE 's/^[[:space:]]+(description .*)$/\1/p' <<<"${block}" | head -n1
}

desc_is_probe() { [[ "$1" == "description \"${PROBE_DESC}\"" || "$1" == "description ${PROBE_DESC}" ]]; }

last_change() {
  http GET /rci/show/last-change
  as_json "${RESP_BODY}"
}

probe7_failsafe() {
  local p=p7_failsafe t desc lc still_present unsaved_after_disarm startup_has
  ORIG_DESC_LINE="$(read_description)" || {
    ev_set "${p}" result '{"skipped": "running-config unreadable"}'
    return 0
  }
  ev_update ".probes[\$p].original_description_present = (\$o != \"\")" --arg p "${p}" --arg o "${ORIG_DESC_LINE}"
  ev_update ".probes[\$p].last_change_before = \$v" --arg p "${p}" --argjson v "$(last_change)"

  FAILSAFE_ARMED=1
  rci_parse "system configuration fail-safe timer reboot 120" || true
  record_parse "${p}" "arm" "system configuration fail-safe timer reboot 120"
  DESC_CHANGED=1
  rci_parse "system description \"${PROBE_DESC}\"" || true
  record_parse "${p}" "change description" "system description \"${PROBE_DESC}\""
  for t in 0 10 20 30 40 50 60; do
    ((t == 0)) || sleep 10
    lc="$(last_change)"
    ev_update ".probes[\$p].samples += [{t: \$t, status: \$s, last_change: \$v}]" \
      --arg p "${p}" --argjson t "${t}" --arg s "${RESP_STATUS}" --argjson v "${lc}"
  done

  # 7b: disarm keeps the change unsaved.
  rci_parse "no system configuration fail-safe timer" && FAILSAFE_ARMED=0
  record_parse "${p}" "disarm" "no system configuration fail-safe timer"
  desc="$(read_description || true)"
  still_present=false
  desc_is_probe "${desc}" && still_present=true
  lc="$(last_change)"
  unsaved_after_disarm="$(jq -c '.unsaved? // null' <<<"${lc}" 2>/dev/null || echo null)"
  ev_update ".probes[\$p].after_disarm = {change_present: \$c, last_change: \$v}" \
    --arg p "${p}" --argjson c "${still_present}" --argjson v "${lc}"

  # Re-arm and commit.
  FAILSAFE_ARMED=1
  rci_parse "system configuration fail-safe timer reboot 120" || true
  record_parse "${p}" "re-arm" "system configuration fail-safe timer reboot 120"
  rci_parse "system configuration fail-safe commit" && FAILSAFE_ARMED=0
  record_parse "${p}" "commit" "system configuration fail-safe commit"
  NEED_SAVE=1
  lc="$(last_change)"
  http GET /ci/startup-config.txt
  startup_has=false
  [[ "${RESP_STATUS}" == "200" ]] && desc_is_probe "$(config_block "${RESP_BODY}" "system" |
    sed -nE 's/^[[:space:]]+(description .*)$/\1/p' | head -n1)" && startup_has=true
  ev_update ".probes[\$p].after_commit = {last_change: \$v, startup_status: \$s, change_in_startup: \$c}" \
    --arg p "${p}" --argjson v "${lc}" --arg s "${RESP_STATUS}" --argjson c "${startup_has}"

  # Restore the original description and save the original state.
  restore_description && DESC_CHANGED=0
  record_parse "${p}" "restore description" "restore original description"
  rci_parse "system configuration save" && NEED_SAVE=0
  record_parse "${p}" "save" "system configuration save"
  ev_update ".probes[\$p].last_change_after_restore = \$v" --arg p "${p}" --argjson v "$(last_change)"

  ev_set "${p}" result "$(jq -nc --argjson c "${still_present}" --argjson u "${unsaved_after_disarm}" \
    --argjson s "${startup_has}" \
    '{change_present_after_disarm: $c, unsaved_after_disarm: $u, change_in_startup_after_commit: $s}')"
}

uptime_s() {
  http GET /rci/show/system
  jq -r '.uptime // empty' <<<"${RESP_BODY}" 2>/dev/null || true
}

probe8_reboot_revert() {
  local p=p8_failsafe_reboot up_before up_after desc reverted rebooted
  if [[ "${KCC_LIVE_ALLOW_REBOOT-}" != "1" ]]; then
    ev_set "${p}" result '{"skipped": "KCC_LIVE_ALLOW_REBOOT is not 1"}'
    return 0
  fi
  ORIG_DESC_LINE="$(read_description)" || return 0
  up_before="$(uptime_s)"
  FAILSAFE_ARMED=1
  rci_parse "system configuration fail-safe timer reboot 120" || true
  record_parse "${p}" "arm" "system configuration fail-safe timer reboot 120"
  DESC_CHANGED=1
  rci_parse "system description \"${PROBE_DESC}-reboot\"" || true
  record_parse "${p}" "unsaved change" "system description \"${PROBE_DESC}-reboot\""
  log "probe 8: idle for 180 s, the router is expected to reboot"
  sleep 180
  : >"${COOKIE_JAR}"
  AUTHENTICATED=0
  local tries=0
  until login; do
    tries=$((tries + 1))
    ((tries < 30)) || break
    sleep 10
  done
  up_after="$(uptime_s)"
  rebooted=false
  [[ -n "${up_before}" && -n "${up_after}" ]] && ((up_after < up_before + 180)) && rebooted=true
  [[ "${rebooted}" == "true" ]] && FAILSAFE_ARMED=0
  desc="$(read_description || true)"
  reverted=true
  [[ "${desc}" == "description \"${PROBE_DESC}-reboot\"" || "${desc}" == "description ${PROBE_DESC}-reboot" ]] && reverted=false
  [[ "${reverted}" == "true" ]] && DESC_CHANGED=0
  ev_set "${p}" result "$(jq -nc --argjson r "${rebooted}" --argjson v "${reverted}" \
    --arg b "${up_before}" --arg a "${up_after}" \
    '{rebooted: $r, change_reverted: $v, uptime_before: $b, uptime_after: $a}')"
}

probe9_country() {
  http GET /rci/show/system/country
  record p9_country "GET /rci/show/system/country"
}

# ---------------------------------------------------------------------------

main() {
  gate_env
  WORK_DIR="$(mktemp -d)"
  chmod 700 -- "${WORK_DIR}"
  COOKIE_JAR="${WORK_DIR}/cookies"
  : >"${COOKIE_JAR}"
  ev_init
  trap cleanup EXIT
  trap 'exit 130' INT TERM

  login record || live_skip "${LOGIN_ERR}"
  gate_serial
  log "serial allowed; running probes"

  probe2_identity
  probe3_parse
  probe4_ns3
  probe5_realm_hash
  probe6_post_only_shows
  probe7_failsafe
  probe8_reboot_revert
  probe9_country
  log "done; evidence in ${EVIDENCE}"
}

main "$@"
