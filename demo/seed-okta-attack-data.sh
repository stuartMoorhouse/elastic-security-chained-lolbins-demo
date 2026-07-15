#!/usr/bin/env bash
#
# seed-okta-attack-data.sh
#
# Seeds synthetic Okta system log events demonstrating a credential stuffing
# and account takeover attack. Idempotent — safe to re-run before every take.
#
# Attack chain (grouped by user.name + source.ip):
#   Stage 1 — credential stuffing: 5 failed logins (INVALID_CREDENTIALS)
#   Stage 2 — MFA fatigue:         2 MFA push failures
#   Stage 3 — access:              1 successful login
#   Stage 4 — post-compromise:     1 privilege grant
#
# Only jsmith@example.com completes the full chain and fires the rule.
# bjones and alee get failed logins only (no MFA, no success — below threshold).
# mwilson (benign IP) has one failed login then success (forgot password).
#
# Reads the Elasticsearch endpoint/credentials from ./shared/env.json
# (written by scripts/configure.sh). Run scripts/configure.sh first if that
# file doesn't exist yet.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_JSON="${REPO_ROOT}/shared/env.json"

DATA_STREAM="logs-okta.system-default"
ATTACKER_IP="203.0.113.66"
BENIGN_IP="198.51.100.20"

log()  { printf '%s\n' "$*"; }
err()  { printf 'ERROR: %s\n' "$*" >&2; }
step() { printf '\n== %s ==\n' "$*"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || { err "'$1' is required but not found on PATH."; exit 1; }
}

require_cmd jq
require_cmd curl
require_cmd date

if [[ ! -f "${ENV_JSON}" ]]; then
    err "${ENV_JSON} not found. Run ./scripts/configure.sh after 'terraform apply' first."
    exit 1
fi

ES_URL="$(jq -r '.elasticsearch_url // empty' "${ENV_JSON}")"
ES_USER="$(jq -r '.elastic_username // empty' "${ENV_JSON}")"
ES_PASSWORD="$(jq -r '.elastic_password // empty' "${ENV_JSON}")"

if [[ -z "${ES_URL}" || -z "${ES_USER}" || -z "${ES_PASSWORD}" ]]; then
    err "${ENV_JSON} is missing elasticsearch_url / elastic_username / elastic_password."
    err "Run ./scripts/configure.sh first."
    exit 1
fi

minutes_ago() {
    local mins="$1"
    if date -u -v-1M +%s >/dev/null 2>&1; then
        date -u -v-"${mins}"M +"%Y-%m-%dT%H:%M:%S.000Z"
    else
        date -u -d "-${mins} minutes" +"%Y-%m-%dT%H:%M:%S.000Z"
    fi
}

es_post() {
    local path="$1" body="$2"
    curl -s -u "${ES_USER}:${ES_PASSWORD}" -H 'Content-Type: application/json' \
        -X POST "${ES_URL%/}${path}" -d "${body}"
}

build_okta_event() {
    local ts="$1" action="$2" outcome="$3" ip="$4" user="$5" reason="${6:-}"
    local outcome_upper
    outcome_upper="$(printf '%s' "${outcome}" | tr '[:lower:]' '[:upper:]')"

    jq -nc \
        --arg ts      "$ts" \
        --arg action  "$action" \
        --arg outcome "$outcome" \
        --arg oupper  "$outcome_upper" \
        --arg ip      "$ip" \
        --arg user    "$user" \
        --arg reason  "$reason" \
        '{
            "@timestamp": $ts,
            "event": {
                "action":   $action,
                "outcome":  $outcome,
                "dataset":  "okta.system",
                "category": ["authentication"],
                "kind":     "event"
            },
            "okta": {
                "event_type": $action,
                "outcome": ({"result": $oupper} +
                    if $reason != "" then {"reason": $reason} else {} end)
            },
            "source":      {"ip": $ip},
            "client":      {"ip": $ip},
            "user":        {"name": $user, "email": $user},
            "data_stream": {"dataset": "okta.system", "namespace": "default", "type": "logs"}
        }'
}

ATTACKER_BULK=""
add() {
    ATTACKER_BULK+="{\"create\":{}}"$'\n'
    ATTACKER_BULK+="$(build_okta_event "$@")"$'\n'
}

# --------------------------------------------------------------------------
# 1. Clear previous take's demo events for these two source IPs
# --------------------------------------------------------------------------
step "Clearing previous take's demo events (${ATTACKER_IP}, ${BENIGN_IP})"

DELETE_BODY="$(jq -n --arg a "${ATTACKER_IP}" --arg b "${BENIGN_IP}" \
    '{query: {terms: {"source.ip": [$a, $b]}}}')"
DELETE_RESPONSE="$(es_post "/${DATA_STREAM}/_delete_by_query?refresh=true&conflicts=proceed" "${DELETE_BODY}")"
DELETED="$(jq -r '.deleted // "unknown"' <<<"${DELETE_RESPONSE}" 2>/dev/null || echo "unknown")"
log "Deleted ${DELETED} previous demo event(s)."

# --------------------------------------------------------------------------
# 2. Attacker IP — credential stuffing across three Okta accounts.
#    bjones and alee get Stage 1 only (no MFA, no success → rule stays quiet).
#    jsmith completes all four stages and fires the rule.
# --------------------------------------------------------------------------
step "Seeding attacker IP ${ATTACKER_IP}"

# bjones: Stage 1 only — 3 failed logins, no further stages
add "$(minutes_ago 45)" "user.session.start" "failure" "$ATTACKER_IP" "bjones@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 43)" "user.session.start" "failure" "$ATTACKER_IP" "bjones@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 41)" "user.session.start" "failure" "$ATTACKER_IP" "bjones@example.com" "INVALID_CREDENTIALS"

# alee: Stage 1 only — 2 failed logins
add "$(minutes_ago 38)" "user.session.start" "failure" "$ATTACKER_IP" "alee@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 36)" "user.session.start" "failure" "$ATTACKER_IP" "alee@example.com" "INVALID_CREDENTIALS"

# jsmith: full attack chain — FIRES the rule
# Stage 1: credential stuffing — 5 failed logins
add "$(minutes_ago 30)" "user.session.start" "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 28)" "user.session.start" "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 26)" "user.session.start" "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 24)" "user.session.start" "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 22)" "user.session.start" "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
# Stage 2: MFA fatigue — 2 push failures
add "$(minutes_ago 20)" "user.authentication.auth_via_mfa" "failure" "$ATTACKER_IP" "jsmith@example.com" "FACTOR_CHALLENGE_TIMEOUT"
add "$(minutes_ago 18)" "user.authentication.auth_via_mfa" "failure" "$ATTACKER_IP" "jsmith@example.com" "FACTOR_CHALLENGE_TIMEOUT"
# Stage 3: access — successful login
add "$(minutes_ago 15)" "user.session.start" "success" "$ATTACKER_IP" "jsmith@example.com"
# Stage 4: post-compromise — privilege grant
add "$(minutes_ago 12)" "user.account.privilege.grant" "success" "$ATTACKER_IP" "jsmith@example.com"

ATTACKER_RESPONSE="$(es_post "/${DATA_STREAM}/_bulk?refresh=true" "${ATTACKER_BULK}")"
if [[ "$(jq -r '.errors' <<<"${ATTACKER_RESPONSE}" 2>/dev/null || echo true)" != "false" ]]; then
    err "Bulk load for attacker IP reported errors:"
    err "${ATTACKER_RESPONSE}"
    exit 1
fi
log "Indexed attacker events for ${ATTACKER_IP}."

# --------------------------------------------------------------------------
# 3. Benign IP — mwilson forgets password, then logs in successfully.
#    No MFA failures, no post-compromise actions → rule does not fire.
# --------------------------------------------------------------------------
step "Seeding benign IP ${BENIGN_IP} (forgot password, below threshold)"

BENIGN_BULK=""
BENIGN_BULK+="{\"create\":{}}"$'\n'
BENIGN_BULK+="$(build_okta_event "$(minutes_ago 10)" "user.session.start" "failure" "$BENIGN_IP" "mwilson@example.com" "INVALID_CREDENTIALS")"$'\n'
BENIGN_BULK+="{\"create\":{}}"$'\n'
BENIGN_BULK+="$(build_okta_event "$(minutes_ago 8)" "user.session.start" "success" "$BENIGN_IP" "mwilson@example.com")"$'\n'

BENIGN_RESPONSE="$(es_post "/${DATA_STREAM}/_bulk?refresh=true" "${BENIGN_BULK}")"
if [[ "$(jq -r '.errors' <<<"${BENIGN_RESPONSE}" 2>/dev/null || echo true)" != "false" ]]; then
    err "Bulk load for benign IP reported errors:"
    err "${BENIGN_RESPONSE}"
    exit 1
fi
log "Indexed 2 events for ${BENIGN_IP}."

step "Done"
log "Seed data loaded into ${DATA_STREAM}:"
log "  ${ATTACKER_IP} / jsmith@example.com -> failed_logins=5, mfa_failures=2, successful_logins=1, post_compromise=1  (FIRES rule)"
log "  ${ATTACKER_IP} / bjones@example.com -> failed_logins=3 only                                                     (does not fire)"
log "  ${ATTACKER_IP} / alee@example.com   -> failed_logins=2 only                                                     (does not fire)"
log "  ${BENIGN_IP}  / mwilson@example.com -> 1 failed + 1 success, no MFA failures                                   (does not fire)"
