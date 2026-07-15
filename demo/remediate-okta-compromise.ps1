<#
    remediate-okta-compromise.ps1

    Runscript response action for the Okta credential stuffing demo
    (authorized Elastic Security demo). Uploaded to the Elastic Defend
    Script library and triggered via a Runscript response action from the
    Workflow, parameterised with the alert's source.ip and the compromised
    Okta username.

    What it does:
      1. Adds an inbound-block Windows Firewall rule for the attacker's
         source IP (network-level containment). Replaces any rule from a
         previous take so re-runs don't stack duplicates.
      2. Disables the local Windows user account that corresponds to the
         compromised Okta account (lateral-movement prevention). Strips
         the email domain to derive the local account name — e.g.
         jsmith@example.com → jsmith. Skips silently if the account
         doesn't exist locally or is already disabled.
      3. Prints a summary of actions taken.

    Safe to re-run: step 1 replaces rather than duplicates the firewall
    rule; step 2 is a no-op if the account is already disabled.

    In a production environment, extend this with an Okta Management API
    call to suspend the user account and terminate active sessions:
      POST /api/v1/users/{userId}/lifecycle/suspend
      DELETE /api/v1/users/{userId}/sessions
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourceIp,

    [string]$CompromisedUser = ""
)

$RuleName = "Elastic-OktaCompromise-Block-$SourceIp"

Write-Output "=== remediate-okta-compromise.ps1 starting ==="
Write-Output "Source IP:        $SourceIp"
Write-Output "Compromised user: $(if ($CompromisedUser) { $CompromisedUser } else { '(none supplied)' })"

# --------------------------------------------------------------------------
# 1. Block the attacker's source IP at the Windows Firewall.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 1: Blocking source IP at the Windows Firewall =="

$existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output "Rule '$RuleName' already exists from a previous take; removing before recreating."
    Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
}

$firewallBlocked = $false
try {
    New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -Action Block `
        -RemoteAddress $SourceIp -Protocol Any -ErrorAction Stop | Out-Null
    $firewallBlocked = $true
    Write-Output "Created inbound block rule '$RuleName' for $SourceIp."
} catch {
    Write-Output "WARNING: failed to create firewall rule: $($_.Exception.Message)"
}

# --------------------------------------------------------------------------
# 2. Disable the local Windows account for the compromised Okta user.
#    Strips the email domain to derive the local account name.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "== Step 2: Disabling local Windows account for compromised user =="

$accountDisabled = $false
$localUsername = ""

if ([string]::IsNullOrWhiteSpace($CompromisedUser)) {
    Write-Output "No -CompromisedUser supplied; skipping account lockout."
} else {
    $localUsername = ($CompromisedUser -split "@")[0].Trim()

    $account = Get-LocalUser -Name $localUsername -ErrorAction SilentlyContinue
    if (-not $account) {
        Write-Output "Local account '$localUsername' not found on this host; skipping."
    } elseif (-not $account.Enabled) {
        Write-Output "Local account '$localUsername' is already disabled."
    } else {
        try {
            Disable-LocalUser -Name $localUsername -ErrorAction Stop
            $accountDisabled = $true
            Write-Output "Disabled local account '$localUsername'."
        } catch {
            Write-Output "WARNING: failed to disable '$localUsername': $($_.Exception.Message)"
        }
    }
}

# --------------------------------------------------------------------------
# 3. Summary.
# --------------------------------------------------------------------------
Write-Output ""
Write-Output "=== Response Summary ==="
Write-Output ("Firewall rule:    " + $(if ($firewallBlocked) { "$RuleName (blocking $SourceIp)" } else { "FAILED to create" }))
Write-Output ("Account disabled: " + $(if ($accountDisabled) { $localUsername } elseif ($CompromisedUser) { "$localUsername (not found or already disabled)" } else { "none supplied" }))
Write-Output "=== remediate-okta-compromise.ps1 complete ==="
