function Send-AuditAlertNotification {
    <#
    .SYNOPSIS
        Dispatches automated alerts for high and critical identity risks via Webhook (Teams, Slack, SIEM).
    .PARAMETER Findings
        Array of findings returned from identity audit routines.
    .PARAMETER WebhookUrl
        Webhook endpoint URI (e.g., Teams, Slack, SIEM Collector).
    .PARAMETER MinimumSeverity
        Minimum severity threshold to trigger an external alert: CRITICAL, HIGH, MEDIUM, LOW. Default: HIGH.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Findings,

        [Parameter(Mandatory = $false)]
        [string]$WebhookUrl,

        [Parameter(Mandatory = $false)]
        [ValidateSet("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        [string]$MinimumSeverity = "HIGH"
    )

    $severityPriority = @{
        "CRITICAL" = 4
        "HIGH"     = 3
        "MEDIUM"   = 2
        "LOW"      = 1
    }

    $minLevel = $severityPriority[$MinimumSeverity]
    $alertableFindings = $Findings | Where-Object {
        $severityPriority.ContainsKey($_.Severity) -and $severityPriority[$_.Severity] -ge $minLevel
    }

    if (-not $alertableFindings -or $alertableFindings.Count -eq 0) {
        Write-Host "[Alert Pipeline] No findings meet the alert threshold ($MinimumSeverity)." -ForegroundColor Gray
        return $false
    }

    Write-Host "[Alert Pipeline] Triggered! $($alertableFindings.Count) findings require immediate security alert." -ForegroundColor Red

    # Build Alert Summary
    $summary = foreach ($f in $alertableFindings) {
        "• [$($f.Severity)] [$($f.RuleId)] $($f.Target): $($f.Description)"
    }
    $summaryText = $summary -join "`n"

    $payload = @{
        title       = "🚨 Entra ID Security Alert: Elevated Identity Risk Detected"
        timestamp   = (Get-Date).ToUniversalTime().ToString("o")
        alertCount  = $alertableFindings.Count
        severity    = $MinimumSeverity
        details     = $summaryText
        findings    = $alertableFindings
    }

    if ($WebhookUrl) {
        try {
            $jsonBody = $payload | ConvertTo-Json -Depth 6
            Invoke-RestMethod -Uri $WebhookUrl -Method POST -Body $jsonBody -ContentType "application/json" -UseBasicParsing | Out-Null
            Write-Host "[Alert Pipeline] Successfully dispatched webhook notification to $WebhookUrl" -ForegroundColor Green
            return $true
        }
        catch {
            Write-Error "[Alert Pipeline] Webhook dispatch failed: $($_.Exception.Message)"
            return $false
        }
    }
    else {
        # Dry-run console output
        Write-Host "----------------- [SIMULATED WEBHOOK ALERT PAYLOAD] -----------------" -ForegroundColor Yellow
        Write-Host "Title: $($payload.title)" -ForegroundColor Yellow
        Write-Host "Alert Count: $($payload.alertCount)" -ForegroundColor Yellow
        Write-Host "$summaryText" -ForegroundColor Yellow
        Write-Host "---------------------------------------------------------------------" -ForegroundColor Yellow
        return $true
    }
}
