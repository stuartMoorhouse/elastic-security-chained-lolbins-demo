#!/bin/bash
################################################################################
# deploy-workflow.sh
#
# Deploys the Okta Credential Stuffing Response workflow to Kibana via the
# Workflows API. Idempotent: deletes the previous workflow (tracked in
# state/workflow-id) before importing the new one.
#
# Called by terraform/workflows.tf as a local-exec provisioner after the
# Elastic Cloud deployment and Azure VM (with Elastic Agent) are ready.
#
# Reads Terraform outputs directly via `terraform output`.
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_DIR="$(dirname "$TERRAFORM_DIR")"
WORKFLOW_DEF="${TERRAFORM_DIR}/workflows/okta-credential-stuffing.yaml"
STATE_DIR="${PROJECT_DIR}/state"
WORKFLOW_ID_FILE="${STATE_DIR}/workflow-id"

log()  { printf '[deploy-workflow] %s\n' "$*"; }
warn() { printf '[deploy-workflow] WARN: %s\n' "$*" >&2; }
err()  { printf '[deploy-workflow] ERROR: %s\n' "$*" >&2; }

# --- Credentials via curl -K (keeps them off the process table) --------------

CURL_AUTH_CONF=""
setup_curl_auth() {
    CURL_AUTH_CONF="$(mktemp)"
    chmod 600 "$CURL_AUTH_CONF"
    printf 'user = "%s:%s"\n' "$1" "$2" > "$CURL_AUTH_CONF"
}
cleanup_curl_auth() { [[ -n "$CURL_AUTH_CONF" ]] && rm -f "$CURL_AUTH_CONF"; }
trap cleanup_curl_auth EXIT

kb() { curl -sSf -K "$CURL_AUTH_CONF" -H "kbn-xsrf: true" "$@"; }
kb_json() { kb -H "Content-Type: application/json" "$@"; }

# =============================================================================
# STEP 1: Read Terraform outputs
# =============================================================================

log "Reading Terraform outputs..."
KIBANA_URL="$(terraform -chdir="$TERRAFORM_DIR" output -raw kibana_url)"
ELASTIC_USER="$(terraform -chdir="$TERRAFORM_DIR" output -raw elastic_username)"
ELASTIC_PASS="$(terraform -chdir="$TERRAFORM_DIR" output -raw elastic_password)"

if [[ -z "$KIBANA_URL" || -z "$ELASTIC_USER" || -z "$ELASTIC_PASS" ]]; then
    err "One or more Terraform outputs are empty. Has 'terraform apply' completed?"
    exit 1
fi

KIBANA_URL="${KIBANA_URL%/}"   # strip trailing slash
setup_curl_auth "$ELASTIC_USER" "$ELASTIC_PASS"
log "Kibana: ${KIBANA_URL}"

# =============================================================================
# STEP 2: Delete previous workflow (idempotency)
# =============================================================================

if [[ -f "$WORKFLOW_ID_FILE" ]]; then
    OLD_ID="$(tr -d '[:space:]' < "$WORKFLOW_ID_FILE")"
    if [[ -n "$OLD_ID" ]]; then
        log "Deleting previous workflow ${OLD_ID}..."
        HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' \
            -K "$CURL_AUTH_CONF" \
            -X DELETE \
            -H "kbn-xsrf: true" \
            "${KIBANA_URL}/api/workflows/workflow/${OLD_ID}" 2>/dev/null)"
        if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "204" ]]; then
            log "  Deleted."
        else
            warn "  Could not delete (HTTP ${HTTP_CODE}) — may already be gone."
        fi
    fi
    rm -f "$WORKFLOW_ID_FILE"
fi

# =============================================================================
# STEP 3: Look up the Windows agent ID from Fleet
#         (the runscript step needs a concrete agent to target)
# =============================================================================

log "Looking up Windows agent from Fleet (policy: *-windows-endpoint-policy)..."

AGENT_ID=""
POLICY_ID=""
ATTEMPT=0
MAX_ATTEMPTS=40   # 40 × 15s = 10 minutes

while [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; do
    ATTEMPT=$(( ATTEMPT + 1 ))

    # Find the agent policy
    POLICIES="$(kb "${KIBANA_URL}/api/fleet/agent_policies?perPage=100" 2>/dev/null || echo '{}')"
    POLICY_ID="$(jq -r '[.items[]? | select(.name | endswith("-windows-endpoint-policy"))][0].id // empty' <<<"$POLICIES")"

    if [[ -n "$POLICY_ID" ]]; then
        # Find a healthy agent enrolled in that policy
        KUERY="policy_id:\"${POLICY_ID}\""
        ENCODED_KUERY="$(jq -rn --arg q "$KUERY" '$q | @uri')"
        AGENTS="$(kb "${KIBANA_URL}/api/fleet/agents?kuery=${ENCODED_KUERY}" 2>/dev/null || echo '{}')"
        STATUS="$(jq -r '.items[0].status // empty' <<<"$AGENTS")"
        AGENT_ID="$(jq -r '.items[0].id // empty' <<<"$AGENTS")"

        if [[ ("$STATUS" == "online" || "$STATUS" == "healthy") && -n "$AGENT_ID" ]]; then
            log "  Found agent ${AGENT_ID} (status: ${STATUS})"
            break
        fi

        log "  Agent status: ${STATUS:-not enrolled yet} (attempt ${ATTEMPT}/${MAX_ATTEMPTS}, retrying in 15s...)"
    else
        log "  Policy not found yet (attempt ${ATTEMPT}/${MAX_ATTEMPTS}, retrying in 15s...)"
    fi

    sleep 15
done

if [[ -z "$AGENT_ID" ]]; then
    warn "No healthy Windows agent found after $(( MAX_ATTEMPTS * 15 ))s."
    warn "Deploying workflow with windows_agent_id=REPLACE_ME — update the Workflow in Kibana after the agent enrolls."
    AGENT_ID="REPLACE_ME"
fi

# =============================================================================
# STEP 4: Substitute the agent ID into the workflow YAML
# =============================================================================

log "Injecting windows_agent_id into workflow YAML..."
WORKFLOW_YAML="$(sed "s|windows_agent_id: \"\"|windows_agent_id: \"${AGENT_ID}\"|" "$WORKFLOW_DEF")"

# =============================================================================
# STEP 5: Import the workflow
# =============================================================================

log "Importing workflow via /api/workflows/workflow..."
WORKFLOW_RESPONSE="$(echo "$WORKFLOW_YAML" \
    | jq -Rs '{yaml: .}' \
    | kb_json -X POST "${KIBANA_URL}/api/workflows/workflow" -d @- 2>/dev/null)"

WORKFLOW_ID="$(jq -r '.id // .data.id // empty' <<<"$WORKFLOW_RESPONSE" 2>/dev/null || echo "")"

if [[ -n "$WORKFLOW_ID" ]]; then
    log "Workflow imported (ID: ${WORKFLOW_ID})"
    mkdir -p "$STATE_DIR"
    echo "$WORKFLOW_ID" > "$WORKFLOW_ID_FILE"
    log "Workflow ID saved to ${WORKFLOW_ID_FILE}"
else
    warn "Could not parse workflow ID. Response:"
    jq . <<<"$WORKFLOW_RESPONSE" 2>/dev/null || echo "$WORKFLOW_RESPONSE"
    warn "The workflow may need to be imported manually via the Kibana Workflows UI."
    warn "Workflow YAML is at: ${WORKFLOW_DEF}"
fi

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
log "====================================="
log "Workflow deployment complete"
log "====================================="
log "Workflow:      Okta Credential Stuffing Response (${WORKFLOW_ID:-manual import needed})"
log "Windows agent: ${AGENT_ID}"
log ""
log "Next step: when creating the AI detection rule in Kibana, add this"
log "Workflow as an action so it fires on every alert."
if [[ -f "$WORKFLOW_ID_FILE" ]]; then
    log "Workflow ID:   $(cat "$WORKFLOW_ID_FILE")"
fi
