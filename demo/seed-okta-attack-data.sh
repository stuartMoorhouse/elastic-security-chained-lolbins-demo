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

next_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
        python3 -c "import uuid; print(uuid.uuid4())"
    fi
}

build_okta_event() {
    local ts="$1" action="$2" outcome="$3" ip="$4" user="$5" reason="${6:-}"
    local outcome_upper uuid
    outcome_upper="$(printf '%s' "${outcome}" | tr '[:lower:]' '[:upper:]')"
    uuid="$(next_uuid)"

    # Map action+outcome to Okta displayMessage, legacyEventType, severity
    local display_msg legacy_type severity
    case "${action}:${outcome_upper}" in
        user.session.start:FAILURE|user.authentication.usernamepassword:FAILURE)
            display_msg="User login to Okta"; legacy_type="core.user_auth.login_failed"; severity="WARN" ;;
        user.session.start:SUCCESS)
            display_msg="User login to Okta"; legacy_type="core.user_auth.login_success"; severity="INFO" ;;
        user.authentication.auth_via_mfa:FAILURE)
            display_msg="Authentication via MFA"; legacy_type="core.user_auth.mfa.factor.attempt_fail"; severity="WARN" ;;
        user.account.privilege.grant:*)
            display_msg="Grant user privilege"; legacy_type="core.user.account.privilege.grant"; severity="INFO" ;;
        *)
            display_msg="${action}"; legacy_type="${action}"; severity="INFO" ;;
    esac

    # Attacker IP — VPN exit node geo + proxy flag
    # Benign IP   — residential US geo
    local city state country postal lat lon as_num as_org isp domain is_proxy threat
    if [[ "${ip}" == "${ATTACKER_IP}" ]]; then
        city="Frankfurt"; state="Hesse"; country="Germany"; postal="60311"
        lat=50.1109;  lon=8.6821
        as_num=205100; as_org="anonymous vpn"; isp="anon hosting"; domain="anonymous.example"
        is_proxy=true; threat="true"
    else
        city="Chicago"; state="Illinois"; country="United States"; postal="60601"
        lat=41.8781; lon=-87.6298
        as_num=7922; as_org="Comcast Cable"; isp="Comcast"; domain="comcast.net"
        is_proxy=false; threat="false"
    fi

    # Build the raw Okta JSON object, then serialise it into the `message` field.
    # The ingest pipeline (logs-okta.system-3.15.0) expects:
    #   message (string) → renamed to event.original → parsed as json.* → mapped to ECS
    local okta_json
    okta_json="$(jq -nc \
        --arg ts          "$ts" \
        --arg uuid        "$uuid" \
        --arg action      "$action" \
        --arg oupper      "$outcome_upper" \
        --arg reason      "$reason" \
        --arg user        "$user" \
        --arg display_msg "$display_msg" \
        --arg legacy_type "$legacy_type" \
        --arg severity    "$severity" \
        --arg ip          "$ip" \
        --arg city        "$city" \
        --arg state       "$state" \
        --arg country     "$country" \
        --arg postal      "$postal" \
        --argjson lat     "$lat" \
        --argjson lon     "$lon" \
        --argjson as_num  "$as_num" \
        --arg as_org      "$as_org" \
        --arg isp         "$isp" \
        --arg domain      "$domain" \
        --argjson is_proxy "$is_proxy" \
        --arg threat      "$threat" \
        '{
            "published":       $ts,
            "uuid":            $uuid,
            "eventType":       $action,
            "displayMessage":  $display_msg,
            "severity":        $severity,
            "version":         "0",
            "legacyEventType": $legacy_type,
            "outcome": {
                "result": $oupper,
                "reason": (if $reason != "" then $reason else null end)
            },
            "actor": {
                "id":          ("00u" + $uuid[0:17]),
                "type":        "User",
                "alternateId": $user,
                "displayName": ($user | split("@")[0] | split(".") |
                                map(. as $w | ($w[0:1] | ascii_upcase) + $w[1:]) | join(" ")),
                "detailEntry": null
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "os":           "Linux",
                    "browser":      "CHROME"
                },
                "zone":      "null",
                "device":    "Computer",
                "id":        null,
                "ipAddress": $ip,
                "geographicalContext": {
                    "city":        $city,
                    "state":       $state,
                    "country":     $country,
                    "postalCode":  $postal,
                    "geolocation": {"lat": $lat, "lon": $lon}
                }
            },
            "authenticationContext": {
                "authenticationProvider": null,
                "credentialProvider":     null,
                "credentialType":         null,
                "issuer":                 null,
                "externalSessionId":      "unknown",
                "interface":              null
            },
            "securityContext": {
                "asNumber": $as_num,
                "asOrg":    $as_org,
                "isp":      $isp,
                "domain":   $domain,
                "isProxy":  $is_proxy
            },
            "debugContext": {
                "debugData": {
                    "requestUri":        "/api/v1/authn",
                    "requestId":         $uuid,
                    "threatSuspected":   $threat,
                    "deviceFingerprint": "a1b2c3d4e5f6a7b8c9d0e1f2"
                }
            },
            "transaction": {"type": "WEB", "id": $uuid, "detail": {}},
            "request": {
                "ipChain": [{
                    "ip":                 $ip,
                    "geographicalContext": {"city": $city, "country": $country},
                    "version":            "V4",
                    "source":             null
                }]
            },
            "target": null
        }')"

    # Wrap in the envelope the ingest pipeline expects: message = Okta JSON string
    jq -nc --arg ts "$ts" --arg msg "$okta_json" \
        '{"@timestamp": $ts, "message": $msg}'
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
    '{query: {bool: {should: [
        {terms: {"source.ip":      [$a, $b]}},
        {terms: {"client.ipAddress": [$a, $b]}}
    ], minimum_should_match: 1}}}')"
DELETE_RESPONSE="$(es_post "/${DATA_STREAM}/_delete_by_query?refresh=true&conflicts=proceed" "${DELETE_BODY}")"
DELETED="$(jq -r '.deleted // "unknown"' <<<"${DELETE_RESPONSE}" 2>/dev/null || echo "unknown")"
log "Deleted ${DELETED} previous demo event(s)."

# --------------------------------------------------------------------------
# 2. Attacker IP — credential stuffing across three Okta accounts.
#    bjones and alee get Stage 1 only (no MFA, no success → rule stays quiet).
#    jsmith completes all four stages and fires the rule.
# --------------------------------------------------------------------------
step "Seeding attacker IP ${ATTACKER_IP}"

# bjones: Stage 1 only — 3 failed logins, no further stages (spray noise alongside jsmith)
# Both event types so any reasonable AI query catches them
add "$(minutes_ago 9)" "user.session.start"               "failure" "$ATTACKER_IP" "bjones@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 8)" "user.authentication.usernamepassword" "failure" "$ATTACKER_IP" "bjones@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 7)" "user.session.start"               "failure" "$ATTACKER_IP" "bjones@example.com" "INVALID_CREDENTIALS"

# alee: Stage 1 only — 2 failed logins
add "$(minutes_ago 9)" "user.session.start"               "failure" "$ATTACKER_IP" "alee@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 8)" "user.authentication.usernamepassword" "failure" "$ATTACKER_IP" "alee@example.com" "INVALID_CREDENTIALS"

# jsmith: full attack chain — FIRES the rule
# Stage 1: credential stuffing — both event types at every attempt so any AI query variant matches
add "$(minutes_ago 9)" "user.session.start"               "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 9)" "user.authentication.usernamepassword" "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 7)" "user.session.start"               "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 7)" "user.authentication.usernamepassword" "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 5)" "user.session.start"               "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
add "$(minutes_ago 5)" "user.authentication.usernamepassword" "failure" "$ATTACKER_IP" "jsmith@example.com" "INVALID_CREDENTIALS"
# Stage 2: MFA fatigue — 2 push failures
add "$(minutes_ago 4)" "user.authentication.auth_via_mfa" "failure" "$ATTACKER_IP" "jsmith@example.com" "FACTOR_CHALLENGE_TIMEOUT"
add "$(minutes_ago 3)" "user.authentication.auth_via_mfa" "failure" "$ATTACKER_IP" "jsmith@example.com" "FACTOR_CHALLENGE_TIMEOUT"
# Stage 3: access — both event types so queries matching user.authentication.* also fire
add "$(minutes_ago 2)" "user.session.start"               "success" "$ATTACKER_IP" "jsmith@example.com"
add "$(minutes_ago 2)" "user.authentication.usernamepassword" "success" "$ATTACKER_IP" "jsmith@example.com"
# Stage 4: post-compromise — privilege grant
add "$(minutes_ago 1)" "user.account.privilege.grant"     "success" "$ATTACKER_IP" "jsmith@example.com"

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
BENIGN_BULK+="$(build_okta_event "$(minutes_ago 9)" "user.session.start" "failure" "$BENIGN_IP" "mwilson@example.com" "INVALID_CREDENTIALS")"$'\n'
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
