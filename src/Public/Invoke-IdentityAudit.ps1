function Invoke-IdentityAudit {
    <#
    .SYNOPSIS
        Master orchestrator for the Automated Systems Telemetry & Identity Auditing Framework.
    .PARAMETER Session
        Connected Microsoft Graph session from Connect-GraphAuditSession.
    .PARAMETER ExportReports
        If specified, exports JSON, CSV, and HTML reports.
    .PARAMETER OutputPath
        Directory path for generated reports.
    .PARAMETER WebhookUrl
        Optional webhook URL to send critical risk alerts.
    .PARAMETER InactivityThresholdDays
        Threshold in days for dormant privileged accounts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Session,

        [Parameter(Mandatory = $false)]
        [switch]$ExportReports,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "./Reports",

        [Parameter(Mandatory = $false)]
        [string]$WebhookUrl,

        [Parameter(Mandatory = $false)]
        [int]$InactivityThresholdDays = 60
    )

    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "   AUTOMATED SYSTEMS TELEMETRY & IDENTITY AUDITING FRAMEWORK   " -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Tenant Target   : $($Session.TenantName) ($($Session.TenantId))" -ForegroundColor Gray
    Write-Host " Operational Mode: $(if ($Session.IsSimulated) { 'Simulation / Testbed' } else { 'Live Microsoft Entra ID' })" -ForegroundColor Gray
    Write-Host " Execution Start : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC" -ForegroundColor Gray
    Write-Host "============================================================`n" -ForegroundColor Cyan

    $allFindings = [System.Collections.Generic.List[PSObject]]::new()

    # Step 1: Audit Privileged Accounts and Telemetry
    Write-Host "[1/3] Executing Privileged Account & Telemetry Detection..." -ForegroundColor Yellow
    $privFindings = Get-PrivilegedAccountTelemetry -Session $Session -InactivityThresholdDays $InactivityThresholdDays
    Write-Host "      -> Found $($privFindings.Count) privileged identity findings." -ForegroundColor Gray
    $privFindings | ForEach-Object { $allFindings.Add($_) }

    # Step 2: Audit Application Permissions and Least Privilege Drift
    Write-Host "[2/3] Evaluating Application Permissions & Least-Privilege Drift..." -ForegroundColor Yellow
    $driftFindings = Test-LeastPrivilegeDrift -Session $Session
    Write-Host "      -> Found $($driftFindings.Count) permission/secret drift findings." -ForegroundColor Gray
    $driftFindings | ForEach-Object { $allFindings.Add($_) }

    # Step 3: Parse Structured Audit Logs for Compromise Indicators
    Write-Host "[3/3] Parsing Structured JSON Directory Audit Logs..." -ForegroundColor Yellow
    $logFindings = Get-AnomalousAuditEvents -Session $Session
    Write-Host "      -> Found $($logFindings.Count) anomalous audit log indicators." -ForegroundColor Gray
    $logFindings | ForEach-Object { $allFindings.Add($_) }

    # Compute Risk Score and Metrics
    $criticalCount = @($allFindings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $highCount     = @($allFindings | Where-Object { $_.Severity -eq "HIGH" }).Count
    $medCount      = @($allFindings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $lowCount      = @($allFindings | Where-Object { $_.Severity -eq "LOW" }).Count

    # Risk Penalty Score (starts at 100, drops with findings)
    $penalty = ($criticalCount * 25) + ($highCount * 15) + ($medCount * 5) + ($lowCount * 2)
    $postureScore = [math]::Max(0, 100 - $penalty)

    $auditSummary = [PSCustomObject]@{
        TenantId          = $Session.TenantId
        TenantName        = $Session.TenantName
        IsSimulated       = $Session.IsSimulated
        ExecutedAtUtc     = (Get-Date).ToUniversalTime().ToString("o")
        PostureScore      = $postureScore
        TotalFindings     = $allFindings.Count
        SeverityBreakdown = @{
            CRITICAL = $criticalCount
            HIGH     = $highCount
            MEDIUM   = $medCount
            LOW      = $lowCount
        }
        Findings          = $allFindings.ToArray()
    }

    Write-Host "`n------------------- AUDIT SUMMARY METRICS -------------------" -ForegroundColor Green
    Write-Host " Identity Posture Score: $postureScore / 100" -ForegroundColor $(if ($postureScore -lt 60) { "Red" } else { "Green" })
    Write-Host " Total Risk Findings   : $($allFindings.Count)" -ForegroundColor White
    Write-Host "   [CRITICAL] : $criticalCount" -ForegroundColor Red
    Write-Host "   [HIGH]     : $highCount" -ForegroundColor DarkYellow
    Write-Host "   [MEDIUM]   : $medCount" -ForegroundColor Yellow
    Write-Host "   [LOW]      : $lowCount" -ForegroundColor Blue
    Write-Host "------------------------------------------------------------`n" -ForegroundColor Green

    # Step 4: Export Reports if requested
    if ($ExportReports) {
        $exported = Export-AuditTelemetryReport -AuditResults $auditSummary -OutputPath $OutputPath -Format "All"
        $auditSummary | Add-Member -MemberType NoteProperty -Name "ReportFiles" -Value $exported
    }

    # Step 5: Webhook Alert Dispatch
    if ($criticalCount -gt 0 -or $highCount -gt 0) {
        Send-AuditAlertNotification -Findings $allFindings.ToArray() -WebhookUrl $WebhookUrl -MinimumSeverity "HIGH" | Out-Null
    }

    return $auditSummary
}
