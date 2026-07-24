#!/usr/bin/env bash
#
# test-query-variants.sh
#
# Tests a range of ES|QL query patterns against the seeded Okta data to verify
# that the seed data is robust enough to fire regardless of which variant the
# AI rule creation tool generates.
#
# A query PASSES if:
#   - jsmith@example.com / 203.0.113.66 appears in results (rule fires)
#   - bjones, alee, mwilson do NOT appear (no false positives)
#
# Run after seed-okta-attack-data.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_JSON="${SCRIPT_DIR}/../shared/env.json"

ES_URL="$(jq -r '.elasticsearch_url' "${ENV_JSON}")"
ES_USER="$(jq -r '.elastic_username' "${ENV_JSON}")"
ES_PASS="$(jq -r '.elastic_password' "${ENV_JSON}")"

PASS=0; FAIL=0

run_query() {
    curl -s -u "${ES_USER}:${ES_PASS}" \
        "${ES_URL%/}/_query" \
        -H 'Content-Type: application/json' \
        -d "{\"query\": $(jq -Rs '.' <<<"$1")}"
}

check() {
    local name="$1" query="$2"
    local result fires_jsmith false_positives

    result="$(run_query "${query}" 2>/dev/null)"

    if echo "${result}" | jq -e '.error' >/dev/null 2>&1; then
        printf "  FAIL  %-55s  ERROR: %s\n" "${name}" "$(echo "${result}" | jq -r '.error.reason // .error.type' 2>/dev/null | head -c 80)"
        FAIL=$((FAIL+1))
        return
    fi

    fires_jsmith="$(echo "${result}" | jq -r '.values[]? | select(.[]) | @json' 2>/dev/null | grep -c "jsmith" || true)"
    false_positives="$(echo "${result}" | jq -r '.values[]? | @json' 2>/dev/null | grep -cE "bjones|alee|mwilson" || true)"

    if [[ "${fires_jsmith}" -ge 1 && "${false_positives}" -eq 0 ]]; then
        printf "  PASS  %s\n" "${name}"
        PASS=$((PASS+1))
    elif [[ "${fires_jsmith}" -eq 0 ]]; then
        printf "  FAIL  %-55s  jsmith not found\n" "${name}"
        FAIL=$((FAIL+1))
    else
        printf "  FAIL  %-55s  false positives: %s\n" "${name}" "$(echo "${result}" | jq -r '.values[]?[6] // .values[]?[4]' 2>/dev/null | grep -E "bjones|alee|mwilson" | tr '\n' ' ')"
        FAIL=$((FAIL+1))
    fi
}

echo ""
echo "Query variant test — $(date -u +%H:%M:%S)"
echo "══════════════════════════════════════════════════════════"

# ── Variant 1: reference query (event.action / event.outcome / ECS fields) ──
check "ECS fields, COUNT(*) WHERE, user.session.start failed login" \
'FROM logs-okta.system-default
| STATS failed_logins = COUNT(*) WHERE event.action == "user.session.start" AND event.outcome == "failure" AND okta.outcome.reason == "INVALID_CREDENTIALS",
        mfa_failures = COUNT(*) WHERE event.action == "user.authentication.auth_via_mfa" AND event.outcome == "failure",
        successful_logins = COUNT(*) WHERE event.action == "user.session.start" AND event.outcome == "success",
        post_compromise = COUNT(*) WHERE event.action == "user.account.privilege.grant",
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY `user.name`, source.ip
| WHERE failed_logins >= 3 AND mfa_failures >= 1 AND successful_logins >= 1 AND post_compromise >= 1
| SORT failed_logins DESC'

# ── Variant 2: okta.event_type / okta.outcome.result fields ──
check "okta.* fields, COUNT(*) WHERE, user.session.start failed login" \
'FROM logs-okta.system-default
| STATS failed_logins = COUNT(*) WHERE okta.event_type == "user.session.start" AND okta.outcome.result == "FAILURE" AND okta.outcome.reason == "INVALID_CREDENTIALS",
        mfa_failures = COUNT(*) WHERE okta.event_type == "user.authentication.auth_via_mfa" AND okta.outcome.result == "FAILURE",
        successful_logins = COUNT(*) WHERE okta.event_type == "user.session.start" AND okta.outcome.result == "SUCCESS",
        post_compromise = COUNT(*) WHERE okta.event_type == "user.account.privilege.grant",
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY okta.actor.alternate_id, okta.client.ip
| WHERE failed_logins >= 3 AND mfa_failures >= 1 AND successful_logins >= 1 AND post_compromise >= 1
| SORT failed_logins DESC'

# ── Variant 3: user.authentication.usernamepassword for failed logins ──
check "okta.* fields, usernamepassword failed login" \
'FROM logs-okta.system-default
| STATS failed_logins = COUNT(*) WHERE okta.event_type == "user.authentication.usernamepassword" AND okta.outcome.result == "FAILURE" AND okta.outcome.reason == "INVALID_CREDENTIALS",
        mfa_failures = COUNT(*) WHERE okta.event_type == "user.authentication.auth_via_mfa" AND okta.outcome.result == "FAILURE",
        successful_logins = COUNT(*) WHERE okta.event_type == "user.session.start" AND okta.outcome.result == "SUCCESS",
        post_compromise = COUNT(*) WHERE okta.event_type == "user.account.privilege.grant",
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY okta.actor.alternate_id, okta.client.ip
| WHERE failed_logins >= 3 AND mfa_failures >= 1 AND successful_logins >= 1 AND post_compromise >= 1
| SORT failed_logins DESC'

# ── Variant 4: user.authentication.* wildcard for successful auth ──
check "okta.* fields, user.authentication.* successful auth" \
'FROM logs-okta.system-default
| STATS failed_logins = COUNT(*) WHERE okta.event_type == "user.session.start" AND okta.outcome.result == "FAILURE" AND okta.outcome.reason == "INVALID_CREDENTIALS",
        mfa_failures = COUNT(*) WHERE okta.event_type == "user.authentication.auth_via_mfa" AND okta.outcome.result == "FAILURE",
        successful_logins = COUNT(*) WHERE okta.event_type LIKE "user.authentication.*" AND okta.outcome.result == "SUCCESS",
        post_compromise = COUNT(*) WHERE okta.event_type == "user.account.privilege.grant",
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY okta.actor.alternate_id, okta.client.ip
| WHERE failed_logins >= 3 AND mfa_failures >= 1 AND successful_logins >= 1 AND post_compromise >= 1
| SORT failed_logins DESC'

# ── Variant 5: EVAL+STATS pattern, user.session.start successful auth ──
check "EVAL+STATS, user.session.start successful auth" \
'FROM logs-okta.system-default
| EVAL is_failed = CASE(okta.event_type == "user.session.start" AND okta.outcome.result == "FAILURE" AND okta.outcome.reason == "INVALID_CREDENTIALS", 1, 0)
| EVAL is_mfa = CASE(okta.event_type == "user.authentication.auth_via_mfa" AND okta.outcome.result == "FAILURE", 1, 0)
| EVAL is_success = CASE(okta.event_type == "user.session.start" AND okta.outcome.result == "SUCCESS", 1, 0)
| EVAL is_post = CASE(okta.event_type == "user.account.privilege.grant" OR okta.event_type LIKE "user.account.privilege.*" OR okta.event_type == "policy.lifecycle.update", 1, 0)
| STATS failed = SUM(is_failed), mfa = SUM(is_mfa), success = SUM(is_success), post = SUM(is_post), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY okta.actor.alternate_id, okta.client.ip
| WHERE failed >= 3 AND mfa >= 1 AND success >= 1 AND post >= 1
| SORT failed DESC'

# ── Variant 6: EVAL+STATS pattern, user.authentication.* successful auth ──
check "EVAL+STATS, user.authentication.* successful auth" \
'FROM logs-okta.system-default
| EVAL is_failed = CASE(okta.event_type == "user.session.start" AND okta.outcome.result == "FAILURE" AND okta.outcome.reason == "INVALID_CREDENTIALS", 1, 0)
| EVAL is_mfa = CASE(okta.event_type == "user.authentication.auth_via_mfa" AND okta.outcome.result == "FAILURE", 1, 0)
| EVAL is_success = CASE(okta.event_type LIKE "user.authentication.*" AND okta.outcome.result == "SUCCESS", 1, 0)
| EVAL is_post = CASE(okta.event_type == "user.account.privilege.grant" OR okta.event_type LIKE "user.account.privilege.*" OR okta.event_type == "policy.lifecycle.update", 1, 0)
| STATS failed = SUM(is_failed), mfa = SUM(is_mfa), success = SUM(is_success), post = SUM(is_post), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY okta.actor.alternate_id, okta.client.ip
| WHERE failed >= 3 AND mfa >= 1 AND success >= 1 AND post >= 1
| SORT failed DESC'

# ── Variant 7: EVAL+STATS, usernamepassword failed login ──
check "EVAL+STATS, usernamepassword failed login" \
'FROM logs-okta.system-default
| EVAL is_failed = CASE(okta.event_type == "user.authentication.usernamepassword" AND okta.outcome.result == "FAILURE" AND okta.outcome.reason == "INVALID_CREDENTIALS", 1, 0)
| EVAL is_mfa = CASE(okta.event_type == "user.authentication.auth_via_mfa" AND okta.outcome.result == "FAILURE", 1, 0)
| EVAL is_success = CASE(okta.event_type == "user.session.start" AND okta.outcome.result == "SUCCESS", 1, 0)
| EVAL is_post = CASE(okta.event_type == "user.account.privilege.grant" OR okta.event_type LIKE "user.account.privilege.*", 1, 0)
| STATS failed = SUM(is_failed), mfa = SUM(is_mfa), success = SUM(is_success), post = SUM(is_post), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY okta.actor.alternate_id, okta.client.ip
| WHERE failed >= 3 AND mfa >= 1 AND success >= 1 AND post >= 1
| SORT failed DESC'

# ── Variant 8: mixed — usernamepassword failed + user.authentication.* success ──
check "EVAL+STATS, usernamepassword failed + user.authentication.* success" \
'FROM logs-okta.system-default
| EVAL is_failed = CASE(okta.event_type == "user.authentication.usernamepassword" AND okta.outcome.result == "FAILURE", 1, 0)
| EVAL is_mfa = CASE(okta.event_type == "user.authentication.auth_via_mfa" AND okta.outcome.result == "FAILURE", 1, 0)
| EVAL is_success = CASE(okta.event_type LIKE "user.authentication.*" AND okta.outcome.result == "SUCCESS", 1, 0)
| EVAL is_post = CASE(okta.event_type == "user.account.privilege.grant" OR okta.event_type LIKE "user.account.privilege.*", 1, 0)
| STATS failed = SUM(is_failed), mfa = SUM(is_mfa), success = SUM(is_success), post = SUM(is_post), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY okta.actor.alternate_id, okta.client.ip
| WHERE failed >= 3 AND mfa >= 1 AND success >= 1 AND post >= 1
| SORT failed DESC'

echo "══════════════════════════════════════════════════════════"
echo "  ${PASS} passed, ${FAIL} failed"
echo ""
