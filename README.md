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

## Setup

Everything is handled by `terraform apply` and `scripts/configure.sh`.

### First-time provisioning

```bash
# 1. Fill in credentials
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# edit terraform/terraform.tfvars — Elastic Cloud API key, Azure credentials, my_ip

# 2. Provision
terraform -chdir=terraform init
terraform -chdir=terraform apply
```

`terraform apply` does all of this in order:
- Creates the Elastic Cloud deployment (Elasticsearch + Kibana)
- Provisions the Azure Windows VM, VNet, NSG, public IP
- Installs and enrolls the Elastic Agent on the VM
- Deploys the Okta Credential Stuffing Response workflow to Kibana and writes its ID to `state/workflow-id`
- Runs `scripts/configure.sh` — writes `shared/env.json`, creates the endpoint response-actions data stream, installs the Okta Fleet integration, waits for the agent to show healthy in Fleet, and uploads `demo/remediate-okta-compromise.ps1` to the Script library (saving its UUID to `state/script-id`)

### Before each demo take (including the first)

```bash
./scripts/prepare-and-reset-demo.sh
```

Seeds fresh Okta attack telemetry with current timestamps, and closes any open alerts and cases from the previous take. Run this before every demo, including the first time after `terraform apply`.

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

### Step 1: Author the detection rule (AI rule creation)

In Kibana: Security → Rules → Create new rule → **AI rule creation**.

Paste this prompt:

> *Find likely Okta account-takeover cases. For each user and source IP, flag the pair when all of these occur: at least 3 failed logins due to invalid credentials, at least one MFA failure, at least one successful login, and at least one post-compromise action — being added to a group or application, being granted account privileges, a sign-on or policy change, or a profile update. Return the user, source IP, a count for each of those four categories, and the first and last timestamps seen, sorted by failed-login count descending.*

Review the generated ES|QL — it uses `COUNT_IF` in a single `STATS` pass, grouped by `user.name` and `source.ip`. Optionally refine. Review the MITRE mapping. Click **Preview rule results** — `jsmith@example.com` should appear (all four stages); `bjones`, `alee`, and `mwilson` should not.

On the **Actions** tab, before saving: add the Workflow as a rule action.

- **Workflow ID:** `cat state/workflow-id`
- **`script_id` input:** `cat state/script-id` (uploaded automatically by `configure.sh`)
- **`endpoint_id` input:** leave as-is — `terraform apply` pre-populated it with the enrolled agent's ID

Click **Apply to creation** and enable the rule.

### Step 2: Detect

Navigate to Security → Alerts. The rule fires immediately on the seeded data — show the alert for `jsmith@example.com`. Walk the aggregation fields (`failed_logins`, `mfa_failures`, `successful_logins`, `post_compromise_events`) to show why this user/IP triggered and the others did not.

### Step 3: Respond — show the auto-created case

Open Security → Cases. The Workflow fired when the alert was created and ran seven automated steps:

1. Opened a case — title, description, severity Critical, MITRE tags.
2. Set status → **in-progress** — signals remediation is underway.
3. Attached the triggering alert to the case.
4. Pinned the attacker IP and compromised account as **observables** (IOCs visible in the case header).
5. Added an **AI analysis comment** (Claude-generated summary of the four-stage attack chain).
6. Ran `remediate-okta-compromise.ps1` via Runscript — blocked `source.ip` at the Windows Firewall and disabled the local account matching the compromised Okta username.
7. Added a remediation summary comment and closed the case.

Walk the case timeline: created → in-progress → observables → AI analysis → remediation → closed. The pitch: one alert, a consistent automated response every time — no manual RDP or ad-hoc scripting required.

## Cleanup

`terraform destroy`
