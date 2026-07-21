# Elastic Security 9.4 Webinar Demo

Self-contained demo of AI-assisted detection, Runscript response, and Workflow-driven case automation, run against a Windows VM enrolled in Elastic Cloud.

## The threat

**Okta credential stuffing and account takeover** — an attacker uses a list of breached credentials to spray multiple Okta accounts, pushes through MFA, and then takes post-compromise actions (privilege escalation, policy changes) once inside. The detection requires the *full four-stage sequence* to be present for the same `user.name` and `source.ip`: failed logins with `INVALID_CREDENTIALS`, MFA failures, a successful login, and at least one post-compromise action. This is what makes it high-fidelity: a user who forgets their password won't match (no MFA failures, no post-compromise), and an attacker stopped at MFA won't match either.

Demo telemetry is synthetic Okta system log events (`logs-okta.system-default`), seeded via `demo/seed-okta-attack-data.sh`. One attacker IP completes the full chain against `jsmith@example.com` (fires the rule); two other accounts (`bjones`, `alee`) get failed logins only; one benign IP (`mwilson`) has a single failed login then success (forgot password — correctly silent).

MITRE: T1110.004 (Credential Stuffing), T1078 (Valid Accounts), T1098 (Account Manipulation).

## Elastic features shown

| Agenda item | Feature |
|---|---|
| AI-assisted detection engineering | **AI rule creation** in Agent Builder — describe the threat in natural language, generate/refine an ES\|QL aggregation rule |
| Automated response & case management | **Workflows**, launched from an alert, combining a **Runscript** response action + centralized **Script library** (Elastic Defend, GA 9.4) to block the `source.ip` and disable accounts, with **Cases** action steps to triage and document the incident |

## Prerequisites

- Infra provisioned (see `CLAUDE.md`): Azure Windows VM + Elastic Cloud, agent enrolled, Elastic Defend installed on the agent policy in detect-only mode (Terraform-managed).
- `demo/remediate-okta-compromise.ps1` uploaded to the Script library (*Remediation Action*).

## Connecting to the VM

The VM enrollment script installs OpenSSH Server, so the simplest way to run response actions or inspect state is SSH from your machine — no RDP client needed. (RDP is also open on 3389 from `my_ip` if you want the GUI.)

Grab connection details from Terraform outputs:

```bash
export VM_IP=$(terraform -chdir=terraform output -raw vm_public_ip)
export VM_USER=$(terraform -chdir=terraform output -raw vm_admin_username)
terraform -chdir=terraform output -raw vm_admin_password   # prints the admin password
```

SSH in (enter the password from above when prompted):

```bash
ssh "${VM_USER}@${VM_IP}"
```

If the password is rejected, copy/paste corruption between terminals (e.g. VS Code's integrated terminal wrapping/mangling long special-character strings) is a common culprit — skip the manual copy entirely and feed the password straight from Terraform to `ssh` with [`sshpass`](https://formulae.brew.sh/formula/sshpass) (`brew install hudochenkov/sshpass/sshpass`):

```bash
sshpass -p "$(terraform -chdir=terraform output -raw vm_admin_password)" ssh "${VM_USER}@${VM_IP}"
```

RDP instead, if preferred:

```bash
open "rdp://full%20address=s:${VM_IP}&username=s:${VM_USER}"   # macOS, Microsoft Remote Desktop app
```

If SSH or RDP hangs on connect, your public IP has likely changed since the NSG rule was last provisioned (it's auto-detected at `apply` time). Re-run `terraform -chdir=terraform apply` — it only updates the NSG rule — then retry.

## Demo steps

Before each take, run `./scripts/reset-demo.sh` — this closes any open alerts and cases from the previous take and re-seeds fresh Okta attack telemetry with current timestamps.

1. **Author (AI detection).** Create a rule → **AI rule creation**. Prompt: *"Find likely Okta account-takeover cases. For each user and source IP, flag the pair when all of these occur: at least 3 failed logins due to invalid credentials, at least one MFA failure, at least one successful login, and at least one post-compromise action — being added to a group or application, being granted account privileges, a sign-on or policy change, or a profile update. Return the user, source IP, a count for each of those four categories, and the first and last timestamps seen, sorted by failed-login count descending."* Review the generated ES|QL — it uses `COUNT_IF` in a single `STATS` pass to count each attack stage independently, grouped by `user.name` and `source.ip`. Optionally refine (e.g. tighten the `okta.outcome.reason` filter, add a time bucket). Review the MITRE mapping. Then click **Preview rule results** — the seeded data is already indexed, so this should surface `jsmith@example.com` from the attacker IP (all four stages present) while `bjones`, `alee`, and `mwilson` are correctly absent. Once satisfied, **Apply to creation** and enable.
2. **Detect.** Show the alert — the preview result now exists as a real alert. Walk the aggregation fields (`failed_logins`, `mfa_failures`, `successful_logins`, `post_compromise_events`) to show why this specific user/IP combination triggered and the others did not.
3. **Respond & automate (Workflow).** The Workflow is deployed automatically by `terraform apply` (see `terraform/workflows.tf` and `terraform/workflows/okta-credential-stuffing.yaml`). The Workflow ID is written to `state/workflow-id`. When creating the AI detection rule in step 1, add this Workflow as a rule action so it fires on every alert. The Workflow runs seven steps in sequence:
   1. `cases.createCase` — opens a new case with title, description, severity (Critical), and MITRE tags.
   2. `cases.setStatus` → **in-progress** — immediately signals that automated remediation is underway.
   3. `cases.addAlerts` — attaches the triggering alert to the case.
   4. `cases.addObservables` — extracts and pins the attacker IP (`source.ip`) as an `ip_address` observable and the compromised account (`user.name`) as a `user` observable; these appear as tagged IOCs in the case, not just text in a comment.
   5. `cases.addComment` — analysis comment summarizing the four-stage attack chain with counts from the aggregation fields.
   6. **Runscript** (`kibana.request` → `/api/endpoint/action/run_script`) — runs `remediate-okta-compromise.ps1` parameterised with the alert's `SourceIp` and `CompromisedUser`, blocking the attacker IP at the Windows Firewall and disabling the corresponding local Windows account.
   7. `cases.addComment` + `cases.setStatus` → **closed** — adds a summary of the actions taken and closes the case.

   Open the auto-created case to show the full timeline: created → in-progress → observables pinned → analysis → remediation confirmed → closed. This is the pitch: one alert, a consistent automated response every time — no manual RDP or one-off script run required.

## Cleanup

`terraform destroy`
