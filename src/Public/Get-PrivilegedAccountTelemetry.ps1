function Get-PrivilegedAccountTelemetry {
    <#
    .SYNOPSIS
        Evaluates directory role assignments and detects inactive or unprotected privileged accounts.
    .PARAMETER Session
        The Graph audit session from Connect-GraphAuditSession.
    .PARAMETER InactivityThresholdDays
        Number of days without sign-in before a privileged account is flagged as dormant (default: 60).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Session,

        [Parameter(Mandatory = $false)]
        [int]$InactivityThresholdDays = 60
    )

    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $thresholdDate = (Get-Date).ToUniversalTime().AddDays(-$InactivityThresholdDays)

    if ($Session.IsSimulated) {
        $mock = Get-MockAuditDataset
        $roles = $mock.Roles
    }
    else {
        # Fetch directory roles and members from Microsoft Graph REST endpoint
        $rolesUri = "https://graph.microsoft.com/v1.0/directoryRoles?`$expand=members(`$select=id,userPrincipalName,displayName,accountEnabled,signInActivity)"
        $roles = Invoke-GraphRestRequest -Uri $rolesUri -AccessToken $Session.AccessToken -FollowPages
    }

    $highPrivilegeRoles = @(
        "Global Administrator",
        "Company Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "User Administrator",
        "Application Administrator"
    )

    foreach ($role in $roles) {
        if ($role.displayName -notin $highPrivilegeRoles) {
            continue
        }

        $members = $role.members
        if (-not $members) { continue }

        foreach ($member in $members) {
            $upn = if ($member.userPrincipalName) { $member.userPrincipalName } else { $member.displayName }
            $lastSignIn = $member.signInActivity.lastSignInDateTime

            # Rule 1: Inactive Privileged Account (ID-AUD-001)
            if ($lastSignIn) {
                $lastSignInDate = [datetime]$lastSignIn
                if ($lastSignInDate -lt $thresholdDate) {
                    $daysSince = [math]::Round(((Get-Date).ToUniversalTime() - $lastSignInDate).TotalDays)
                    $findings.Add((Format-AuditFinding `
                        -RuleId "ID-AUD-001" `
                        -Severity "HIGH" `
                        -Category "PrivilegedIdentity" `
                        -Target $upn `
                        -Description "Privileged account with role '$($role.displayName)' has been inactive for $daysSince days (Threshold: $InactivityThresholdDays days)." `
                        -Remediation "Review necessity of administrative role. Strip role or deactivate dormant identity to prevent credential stuffing or persistence." `
                        -Evidence @{
                            RoleName             = $role.displayName
                            LastSignInDateTime   = $lastSignIn
                            DaysInactive         = $daysSince
                            AccountEnabled       = $member.accountEnabled
                        }))
                }
            }
            elseif ($member.accountEnabled) {
                # Account enabled but has NEVER signed in
                $findings.Add((Format-AuditFinding `
                    -RuleId "ID-AUD-002" `
                    -Severity "MEDIUM" `
                    -Category "PrivilegedIdentity" `
                    -Target $upn `
                    -Description "Active privileged account '$upn' in role '$($role.displayName)' has no recorded sign-in telemetry." `
                    -Remediation "Confirm if this account was provisioned in error. Remove unmonitored privileged accounts." `
                    -Evidence @{
                        RoleName       = $role.displayName
                        AccountEnabled = $member.accountEnabled
                    }))
            }

            # Rule 2: Unprotected Privileged Account (Missing MFA) (ID-AUD-003)
            if ($member.mfaEnrolled -eq $false -or ($role.displayName -eq "Global Administrator" -and $member.mfaEnrolled -ne $true)) {
                $findings.Add((Format-AuditFinding `
                    -RuleId "ID-AUD-003" `
                    -Severity "CRITICAL" `
                    -Category "PrivilegedIdentity" `
                    -Target $upn `
                    -Description "Highly privileged identity in '$($role.displayName)' does not have enforced Multi-Factor Authentication (MFA)." `
                    -Remediation "Immediately enforce Conditional Access MFA policy or Phishing-Resistant FIDO2 credentials on all administrative identities." `
                    -Evidence @{
                        RoleName    = $role.displayName
                        MfaEnrolled = $false
                    }))
            }
        }
    }

    return $findings.ToArray()
}
