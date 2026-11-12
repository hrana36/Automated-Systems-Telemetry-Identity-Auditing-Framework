function Get-AnomalousAuditEvents {
    <#
    .SYNOPSIS
        Parses structured Microsoft Graph audit logs to detect anomalous identity activities and privilege elevations.
    .PARAMETER Session
        The Graph audit session from Connect-GraphAuditSession.
    .PARAMETER LookbackHours
        Number of hours of audit telemetry to analyze (default: 48).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Session,

        [Parameter(Mandatory = $false)]
        [int]$LookbackHours = 48
    )

    $findings = [System.Collections.Generic.List[PSObject]]::new()
    $sinceTime = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString("yyyy-MM-ddTHH:mm:ssZ")

    if ($Session.IsSimulated) {
        $mock = Get-MockAuditDataset
        $auditLogs = $mock.AuditLogs
    }
    else {
        $filter = "`$filter=activityDateTime ge $sinceTime"
        $logsUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter"
        $auditLogs = Invoke-GraphRestRequest -Uri $logsUri -AccessToken $Session.AccessToken -FollowPages
    }

    foreach ($log in $auditLogs) {
        $actor = if ($log.initiatedBy.user.userPrincipalName) {
            $log.initiatedBy.user.userPrincipalName
        } elseif ($log.initiatedBy.app.displayName) {
            $log.initiatedBy.app.displayName
        } else {
            "System / Unknown"
        }

        $actorIp = $log.initiatedBy.user.ipAddress

        # Detection 1: Administrative Privilege Elevation (ID-AUD-201)
        if ($log.activityDisplayName -match "Add member to role" -and $log.category -eq "RoleManagement") {
            $targetRole = ($log.targetResources | Where-Object { $_.type -eq "Role" }).displayName
            if ($targetRole -match "Global Administrator|Privileged Role Administrator|Company Administrator") {
                $findings.Add((Format-AuditFinding `
                    -RuleId "ID-AUD-201" `
                    -Severity "CRITICAL" `
                    -Category "AnomalousLog" `
                    -Target "$targetRole elevation initiated by $actor" `
                    -Description "High-privilege role '$targetRole' was assigned. Initiator: $actor (Source IP: $actorIp)." `
                    -Remediation "Verify change ticket. If unapproved, immediately revoke assignment and initiate incident triage for compromised identity." `
                    -Evidence @{
                        EventTime     = $log.activityDateTime
                        Activity      = $log.activityDisplayName
                        Initiator     = $actor
                        SourceIp      = $actorIp
                        AssignedRole  = $targetRole
                    }))
            }
        }

        # Detection 2: Broad Tenant Application Consent Grant (ID-AUD-202)
        if ($log.activityDisplayName -match "Consent to application") {
            $targetApp = ($log.targetResources | Where-Object { $_.type -eq "Application" }).displayName
            $findings.Add((Format-AuditFinding `
                -RuleId "ID-AUD-202" `
                -Severity "HIGH" `
                -Category "AnomalousLog" `
                -Target "$targetApp (Consented by $actor)" `
                -Description "Tenant-wide admin consent was granted to application '$targetApp' by '$actor' from IP $actorIp." `
                -Remediation "Review permissions granted to this application. If unauthorized or suspicious, revoke consent and invalidate tokens." `
                -Evidence @{
                    EventTime       = $log.activityDateTime
                    Activity        = $log.activityDisplayName
                    Initiator       = $actor
                    SourceIp        = $actorIp
                    ApplicationName = $targetApp
                }))
        }
    }

    return $findings.ToArray()
}
