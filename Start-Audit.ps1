<#
.SYNOPSIS
    Convenience entrypoint script to launch the Automated Systems Telemetry & Identity Auditing Framework.
.EXAMPLE
    .\Start-Audit.ps1 -SimulationMode
.EXAMPLE
    .\Start-Audit.ps1 -TenantId "your-tenant-id" -ClientId "your-client-id" -ClientSecret "your-secret"
#>
[CmdletBinding(DefaultParameterSetName = "Simulation")]
param(
    [Parameter(ParameterSetName = "Simulation")]
    [switch]$SimulationMode,

    [Parameter(Mandatory = $true, ParameterSetName = "Live")]
    [string]$TenantId,

    [Parameter(Mandatory = $true, ParameterSetName = "Live")]
    [string]$ClientId,

    [Parameter(Mandatory = $true, ParameterSetName = "Live")]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$WebhookUrl,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [int]$InactivityThresholdDays = 60
)

$ErrorActionPreference = "Stop"

if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "Reports"
}

# Import Framework Module
$modulePath = Join-Path $PSScriptRoot "src\IdentityAuditor.psd1"
Write-Host "[Launcher] Importing IdentityAuditor module from $modulePath..." -ForegroundColor Cyan
Import-Module $modulePath -Force

# Establish Session
if ($SimulationMode -or (-not $TenantId)) {
    $session = Connect-GraphAuditSession -Simulation
}
else {
    $session = Connect-GraphAuditSession -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
}

# Execute Comprehensive Audit
$results = Invoke-IdentityAudit `
    -Session $session `
    -ExportReports `
    -OutputPath $OutputPath `
    -WebhookUrl $WebhookUrl `
    -InactivityThresholdDays $InactivityThresholdDays

Write-Host "[Launcher] Execution finished successfully." -ForegroundColor Green
return $results
