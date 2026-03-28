<#
.SYNOPSIS
    Retrieves and displays all Conditional Access policies and their enforcement state from Microsoft Entra ID via Microsoft Graph.

.DESCRIPTION
    This script connects to Microsoft Graph using the Policy.Read.All scope and enumerates
    all Conditional Access (CA) policies configured in the tenant. It outputs each policy's
    display name and current state (enabled, disabled, or enabledForReportingButNotEnforced)
    so administrators can quickly audit whether critical hardening policies — such as
    'Require MFA for All Users' and 'Require Compliant Device' — are actively enforced
    rather than sitting in report-only mode.

    This is a key step in validating Intune and Entra ID hardening posture following
    guidance derived from breach patterns like the Stryker incident, where misconfigured
    or absent CA policies allowed attackers to bypass MFA and device compliance gates.

    Prerequisites:
      - Microsoft.Graph PowerShell SDK installed (Install-Module Microsoft.Graph)
      - Permissions: Policy.Read.All (delegated or application)
      - Microsoft Entra ID P1 or P2 license (P2 required for risk-based CA)
      - Run as Global Administrator, Security Administrator, or a role with CA read access

    What to look for in output:
      - State: 'enabled'                          → Policy is actively enforced. GOOD.
      - State: 'disabled'                          → Policy exists but does nothing. REVIEW.
      - State: 'enabledForReportingButNotEnforced' → Report-only mode, not blocking. CHANGE TO ENABLED.

.NOTES
    Author:      Souhaiel Morhag
    Company:     MSEndpoint.com
    Blog:        https://msendpoint.com
    Academy:     https://app.msendpoint.com/academy
    LinkedIn:    https://linkedin.com/in/souhaiel-morhag
    GitHub:      https://github.com/Msendpoint
    License:     MIT

.EXAMPLE
    .\Get-IntuneCAHardeningAudit.ps1

    Connects to Microsoft Graph interactively and lists all CA policies with their state.
    Review any policy showing 'enabledForReportingButNotEnforced' and switch it to 'enabled'
    in the Entra admin center immediately.

.EXAMPLE
    .\Get-IntuneCAHardeningAudit.ps1 -ExportCsv

    Connects to Microsoft Graph and exports the CA policy audit results to a timestamped
    CSV file in the current directory for documentation or SIEM ingestion.
#>

[CmdletBinding()]
param (
    # When specified, exports the policy audit results to a CSV file
    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv
)

#region --- Dependency Check ---
# Ensure the Microsoft.Graph module is available before attempting to connect
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.SignIns)) {
    Write-Warning "The 'Microsoft.Graph.Identity.SignIns' module is not installed."
    Write-Warning "Run: Install-Module Microsoft.Graph -Scope CurrentUser -Force"
    exit 1
}
#endregion

#region --- Graph Connection ---
try {
    Write-Host "[*] Connecting to Microsoft Graph with Policy.Read.All scope..." -ForegroundColor Cyan

    # Connect using delegated permissions — prompts for interactive sign-in
    # For unattended/service principal use, replace with Connect-MgGraph -ClientId ... -TenantId ... -CertificateThumbprint ...
    Connect-MgGraph -Scopes "Policy.Read.All" -ErrorAction Stop

    Write-Host "[+] Successfully connected to Microsoft Graph." -ForegroundColor Green
}
catch {
    Write-Error "[!] Failed to connect to Microsoft Graph. Error: $_"
    exit 1
}
#endregion

#region --- Retrieve Conditional Access Policies ---
try {
    Write-Host "`n[*] Retrieving all Conditional Access policies..." -ForegroundColor Cyan

    $caPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop

    if (-not $caPolicies -or $caPolicies.Count -eq 0) {
        Write-Warning "[!] No Conditional Access policies found in this tenant."
        Write-Warning "    This is a critical security gap. Configure CA policies immediately."
        exit 0
    }

    Write-Host "[+] Found $($caPolicies.Count) Conditional Access policy/policies." -ForegroundColor Green
}
catch {
    Write-Error "[!] Failed to retrieve Conditional Access policies. Error: $_"
    exit 1
}
#endregion

#region --- Build Audit Results ---
# Map each policy to a clear audit object with actionable state labels
$auditResults = foreach ($policy in $caPolicies) {

    # Translate raw state values into human-readable risk indicators
    $stateLabel = switch ($policy.State) {
        'enabled'                          { 'ENFORCED - OK' }
        'disabled'                         { 'DISABLED - REVIEW' }
        'enabledForReportingButNotEnforced' { 'REPORT-ONLY - CHANGE TO ENABLED NOW' }
        default                            { "UNKNOWN STATE: $($policy.State)" }
    }

    [PSCustomObject]@{
        PolicyId    = $policy.Id
        DisplayName = $policy.DisplayName
        State       = $policy.State
        Audit       = $stateLabel
    }
}
#endregion

#region --- Display Results ---
Write-Host "`n===== Conditional Access Policy Audit Results =====" -ForegroundColor Yellow
$auditResults | Format-Table -AutoSize -Property DisplayName, State, Audit

# Surface policies that require immediate attention
$atRisk = $auditResults | Where-Object { $_.State -ne 'enabled' }

if ($atRisk) {
    Write-Warning "`n[!] The following $($atRisk.Count) policy/policies are NOT actively enforced:"
    $atRisk | ForEach-Object {
        Write-Warning "    - '$($_.DisplayName)' | State: $($_.State) | Action: $($_.Audit)"
    }
    Write-Warning "`n    Policies in report-only or disabled state provide NO protection."
    Write-Warning "    Update them in: Entra Admin Center → Protection → Conditional Access → Policies"
} else {
    Write-Host "`n[+] All Conditional Access policies are in 'enabled' (enforced) state. Good posture." -ForegroundColor Green
}
#endregion

#region --- Optional CSV Export ---
if ($ExportCsv) {
    try {
        $timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
        $exportPath = Join-Path -Path (Get-Location) -ChildPath "CA_Policy_Audit_$timestamp.csv"

        $auditResults | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop

        Write-Host "`n[+] Audit results exported to: $exportPath" -ForegroundColor Green
    }
    catch {
        Write-Error "[!] Failed to export CSV. Error: $_"
    }
}
#endregion

#region --- Disconnect ---
try {
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    Write-Host "`n[*] Disconnected from Microsoft Graph." -ForegroundColor Cyan
}
catch {
    # Non-fatal — session will expire naturally
    Write-Verbose "Note: Explicit disconnect failed (session may already be closed)."
}
#endregion
