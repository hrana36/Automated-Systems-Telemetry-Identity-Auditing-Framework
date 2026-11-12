function Test-LeastPrivilegeDrift {
    <#
    .SYNOPSIS
        Evaluates application permission delegations, client credentials, and least-privilege configuration drifts.
    .PARAMETER Session
        The Graph audit session from Connect-GraphAuditSession.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Session
    )

    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $now = (Get-Date).ToUniversalTime()

    if ($Session.IsSimulated) {
        $mock = Get-MockAuditDataset
        $applications = $mock.Applications
    }
    else {
        # Query Graph API for registered applications and required permissions
        $appsUri = "https://graph.microsoft.com/v1.0/applications?`$select=id,appId,displayName,createdDateTime,requiredResourceAccess,passwordCredentials"
        $applications = Invoke-GraphRestRequest -Uri $appsUri -AccessToken $Session.AccessToken -FollowPages
    }

    # Known high-risk Microsoft Graph permission GUIDs and names
    $highRiskGraphPermissions = @{
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = @{ Name = "RoleManagement.ReadWrite.Directory"; Severity = "CRITICAL"; Desc = "Can assign any directory role including Global Admin to any entity." }
        "7ab1d382-f21e-4acd-a863-ba3e13f7da61" = @{ Name = "Directory.ReadWrite.All"; Severity = "HIGH"; Desc = "Full write access to the entire enterprise directory." }
        "06b708e9-e30c-43ee-8387-25e4443474f2" = @{ Name = "AppRoleAssignment.ReadWrite.All"; Severity = "CRITICAL"; Desc = "Can grant application permissions without administrator approval." }
        "e2a3a72e-5f79-4c64-b1b1-878b674786c9" = @{ Name = "Mail.ReadWrite"; Severity = "HIGH"; Desc = "Can read and write emails in all enterprise mailboxes." }
    }

    foreach ($app in $applications) {
        $appLabel = "$($app.displayName) (AppId: $($app.appId))"

        # Rule 1: High-Risk Permission Delegation Drift (ID-AUD-101)
        if ($app.requiredResourceAccess) {
            foreach ($res in $app.requiredResourceAccess) {
                if ($res.resourceAccess) {
                    foreach ($perm in $res.resourceAccess) {
                        if ($highRiskGraphPermissions.ContainsKey($perm.id)) {
                            $meta = $highRiskGraphPermissions[$perm.id]
                            $findings.Add((Format-AuditFinding `
                                -RuleId "ID-AUD-101" `
                                -Severity $meta.Severity `
                                -Category "PermissionDelegation" `
                                -Target $appLabel `
                                -Description "Application is granted dangerous high-privilege permission: $($meta.Name). $($meta.Desc)" `
                                -Remediation "Restrict application to granular, least-privilege scopes. Replace tenant-wide write scopes with scoped resource assignments." `
                                -Evidence @{
                                    PermissionId   = $perm.id
                                    PermissionName = $meta.Name
                                    AccessType     = $perm.type
                                }))
                        }
                    }
                }
            }
        }

        # Rule 2: Client Secret Lifetime & Expiry Drift (ID-AUD-102 & ID-AUD-103)
        if ($app.passwordCredentials) {
            foreach ($secret in $app.passwordCredentials) {
                if ($secret.endDateTime) {
                    $expiry = [datetime]$secret.endDateTime
                    $daysRemaining = [math]::Round(($expiry - $now).TotalDays)

                    if ($daysRemaining -lt 0) {
                        # Expired secret
                        $findings.Add((Format-AuditFinding `
                            -RuleId "ID-AUD-102" `
                            -Severity "LOW" `
                            -Category "DriftDetection" `
                            -Target $appLabel `
                            -Description "Application secret '$($secret.displayName)' expired $([math]::Abs($daysRemaining)) days ago but remains attached." `
                            -Remediation "Remove expired credentials to maintain clean service principal hygiene." `
                            -Evidence @{
                                SecretName  = $secret.displayName
                                ExpiryDate  = $secret.endDateTime
                                Status      = "Expired"
                            }))
                    }
                    elseif ($daysRemaining -gt 730) {
                        # Excessive lifetime (> 2 years) - drift from security policy
                        $findings.Add((Format-AuditFinding `
                            -RuleId "ID-AUD-103" `
                            -Severity "MEDIUM" `
                            -Category "DriftDetection" `
                            -Target $appLabel `
                            -Description "Application secret '$($secret.displayName)' has an excessive lifetime ($([math]::Round($daysRemaining / 365, 1)) years). Maximum recommended is 180-365 days." `
                            -Remediation "Rotate secret and configure credential lifetime policies with automated rotation or Managed Identities." `
                            -Evidence @{
                                SecretName    = $secret.displayName
                                ExpiryDate    = $secret.endDateTime
                                DaysRemaining = $daysRemaining
                            }))
                    }
                }
            }
        }
    }

    return $findings.ToArray()
}
