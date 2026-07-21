# Deploy the Okta Credential Stuffing Response workflow via the Kibana Workflows API.
#
# Runs after the Azure VM extension finishes (agent installation has started).
# The deploy script polls Fleet for up to 10 minutes waiting for the agent to
# enroll and go healthy before injecting its ID into the workflow YAML and
# posting it to /api/workflows/workflow.
#
# The workflow ID is saved to state/workflow-id for idempotent re-deploys and
# teardown. On destroy, the workflow is deleted from Kibana.

resource "terraform_data" "workflow" {
  depends_on = [azurerm_virtual_machine_extension.elastic_agent]

  input = {
    kibana_url = ec_deployment.main.kibana.https_endpoint
    username   = ec_deployment.main.elasticsearch_username
    password   = ec_deployment.main.elasticsearch_password
    # Change this hash to force re-deploy when the workflow YAML changes.
    workflow_hash = filemd5("${path.module}/workflows/okta-credential-stuffing.yaml")
  }

  provisioner "local-exec" {
    command = "bash ${path.module}/scripts/deploy-workflow.sh"
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      WORKFLOW_ID_FILE="${path.root}/../state/workflow-id"
      if [[ -f "$WORKFLOW_ID_FILE" ]]; then
        WORKFLOW_ID="$(tr -d '[:space:]' < "$WORKFLOW_ID_FILE")"
        CURL_AUTH="$(mktemp)" && chmod 600 "$CURL_AUTH"
        printf 'user = "%s:%s"\n' "${self.input.username}" "${self.input.password}" > "$CURL_AUTH"
        curl -s -o /dev/null -w "Delete workflow HTTP %%{http_code}\n" \
          -X DELETE \
          -H "kbn-xsrf: true" \
          -K "$CURL_AUTH" \
          "${self.input.kibana_url}/api/workflows/workflow/$WORKFLOW_ID"
        rm -f "$CURL_AUTH" "$WORKFLOW_ID_FILE"
      else
        echo "No state/workflow-id file found — nothing to delete."
      fi
    EOT
  }
}
