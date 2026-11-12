function Export-AuditTelemetryReport {
    <#
    .SYNOPSIS
        Exports structured audit telemetry and generates SIEM JSON, CSV, and an HTML executive security report.
    .PARAMETER AuditResults
        The audit object returned from Invoke-IdentityAudit.
    .PARAMETER OutputPath
        Directory to write reports into (defaults to ./Reports).
    .PARAMETER Format
        Formats to generate: All, JSON, HTML, CSV (default: All).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$AuditResults,

        [Parameter(Mandatory = $false)]
        [string]$OutputPath = "./Reports",

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "JSON", "HTML", "CSV")]
        [string]$Format = "All"
    )

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $exportedFiles = @{}

    # 1. Structured JSON (SIEM Ingestion Format)
    if ($Format -in @("All", "JSON")) {
        $jsonFile = Join-Path $OutputPath "identity-audit-findings-$timestamp.json"
        $AuditResults | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonFile -Encoding utf8
        $exportedFiles["JSON"] = (Resolve-Path $jsonFile).Path
    }

    # 2. CSV Export
    if ($Format -in @("All", "CSV")) {
        $csvFile = Join-Path $OutputPath "identity-audit-findings-$timestamp.csv"
        $AuditResults.Findings | Select-Object FindingId, TimestampUtc, Severity, Category, Target, Description, Remediation |
            Export-Csv -Path $csvFile -NoTypeInformation -Encoding utf8
        $exportedFiles["CSV"] = (Resolve-Path $csvFile).Path
    }

    # 3. Modern Cyber Audit HTML Dashboard
    if ($Format -in @("All", "HTML")) {
        $htmlFile = Join-Path $OutputPath "identity-audit-report-$timestamp.html"

        $criticalCount = ($AuditResults.Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highCount     = ($AuditResults.Findings | Where-Object { $_.Severity -eq "HIGH" }).Count
        $medCount      = ($AuditResults.Findings | Where-Object { $_.Severity -eq "MEDIUM" }).Count
        $lowCount      = ($AuditResults.Findings | Where-Object { $_.Severity -eq "LOW" }).Count
        $totalCount    = $AuditResults.Findings.Count

        $findingsRows = foreach ($f in $AuditResults.Findings) {
            $badgeColor = switch ($f.Severity) {
                "CRITICAL" { "#dc2626" }
                "HIGH"     { "#ea580c" }
                "MEDIUM"   { "#d97706" }
                "LOW"      { "#2563eb" }
                Default    { "#64748b" }
            }
            "<tr>
                <td><span style='background-color:$badgeColor;color:white;padding:3px 8px;border-radius:4px;font-weight:600;font-size:0.8rem;'>$($f.Severity)</span></td>
                <td><code>$($f.RuleId)</code></td>
                <td><strong>$($f.Category)</strong></td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($f.Target))</td>
                <td>$([System.Web.HttpUtility]::HtmlEncode($f.Description))</td>
                <td style='color:#059669;font-size:0.85rem;'>$([System.Web.HttpUtility]::HtmlEncode($f.Remediation))</td>
            </tr>"
        }

        $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Identity Telemetry & Security Audit Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }
        .container { max-width: 1200px; margin: 0 auto; }
        header { border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }
        h1 { margin: 0 0 8px 0; color: #38bdf8; font-size: 1.8rem; }
        .meta { color: #94a3b8; font-size: 0.9rem; }
        .metric-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .card { background: #1e293b; border-radius: 8px; padding: 16px; border: 1px solid #334155; }
        .card .title { font-size: 0.85rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
        .card .value { font-size: 2rem; font-weight: 700; margin-top: 4px; }
        .critical { color: #ef4444; }
        .high { color: #f97316; }
        .medium { color: #f59e0b; }
        .low { color: #3b82f6; }
        .total { color: #38bdf8; }
        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; font-size: 0.9rem; }
        th, td { padding: 12px 14px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #cbd5e1; font-weight: 600; }
        tr:hover { background: #243249; }
        code { background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; font-family: Consolas, monospace; }
        footer { margin-top: 32px; text-align: center; color: #64748b; font-size: 0.8rem; border-top: 1px solid #334155; padding-top: 16px; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Automated Identity Security & Telemetry Audit Report</h1>
            <div class="meta">
                <span>Tenant: <strong>$($AuditResults.TenantName)</strong> ($($AuditResults.TenantId))</span> |
                <span>Execution Time: $($AuditResults.ExecutedAtUtc)</span> |
                <span>Mode: $(if ($AuditResults.IsSimulated) { "Simulation / Testbed" } else { "Live Entra ID Production" })</span>
            </div>
        </header>

        <div class="metric-cards">
            <div class="card"><div class="title">Total Findings</div><div class="value total">$totalCount</div></div>
            <div class="card"><div class="title">Critical Risks</div><div class="value critical">$criticalCount</div></div>
            <div class="card"><div class="title">High Risks</div><div class="value high">$highCount</div></div>
            <div class="card"><div class="title">Medium Risks</div><div class="value medium">$medCount</div></div>
            <div class="card"><div class="title">Low Risks</div><div class="value low">$lowCount</div></div>
        </div>

        <h2>Detailed Security Findings & Drift Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Rule ID</th>
                    <th>Category</th>
                    <th>Target Entity</th>
                    <th>Description</th>
                    <th>Remediation Action</th>
                </tr>
            </thead>
            <tbody>
                $($findingsRows -join "`n")
            </tbody>
        </table>

        <footer>
            Automated Systems Telemetry &amp; Identity Auditing Framework &bull; Designed by Md Habibur Rahaman Rana
        </footer>
    </div>
</body>
</html>
"@
        Set-Content -Path $htmlFile -Value $htmlContent -Encoding utf8
        $exportedFiles["HTML"] = (Resolve-Path $htmlFile).Path
    }

    Write-Host "[Report Generator] Telemetry artifacts created successfully:" -ForegroundColor Green
    foreach ($kv in $exportedFiles.GetEnumerator()) {
        Write-Host "  -> $($kv.Key): $($kv.Value)" -ForegroundColor Gray
    }

    return $exportedFiles
}
