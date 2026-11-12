# IdentityAuditor.psm1 - Root Module Loader

$publicPath = Join-Path $PSScriptRoot "Public"
$privatePath = Join-Path $PSScriptRoot "Private"

# Dot-source Private helper functions first
if (Test-Path $privatePath) {
    Get-ChildItem -Path $privatePath -Filter "*.ps1" | ForEach-Object {
        . $_.FullName
    }
}

# Dot-source Public exported functions
if (Test-Path $publicPath) {
    Get-ChildItem -Path $publicPath -Filter "*.ps1" | ForEach-Object {
        . $_.FullName
    }
}

Export-ModuleMember -Function @(
    "Connect-GraphAuditSession",
    "Invoke-IdentityAudit",
    "Get-PrivilegedAccountTelemetry",
    "Test-LeastPrivilegeDrift",
    "Get-AnomalousAuditEvents",
    "Export-AuditTelemetryReport",
    "Send-AuditAlertNotification"
)
