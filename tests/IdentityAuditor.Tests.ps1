# IdentityAuditor.Tests.ps1 - Automated Unit & Integration Tests

$moduleManifest = Join-Path $PSScriptRoot "..\src\IdentityAuditor.psd1"
Import-Module (Resolve-Path $moduleManifest) -Force

Describe "IdentityAuditor Module Integrity" {
    It "Successfully imports the IdentityAuditor module without errors" {
        $mod = Get-Module IdentityAuditor
        ($null -ne $mod) | Should Be $true
    }

    It "Exports all required public cmdlets" {
        $expectedCmdlets = @(
            "Connect-GraphAuditSession",
            "Invoke-IdentityAudit",
            "Get-PrivilegedAccountTelemetry",
            "Test-LeastPrivilegeDrift",
            "Get-AnomalousAuditEvents",
            "Export-AuditTelemetryReport",
            "Send-AuditAlertNotification"
        )
        $exported = (Get-Module IdentityAuditor).ExportedFunctions.Keys
        foreach ($cmd in $expectedCmdlets) {
            ($exported -contains $cmd) | Should Be $true
        }
    }
}

Describe "Session Management & Telemetry Engine" {
    It "Initializes a valid simulated session" {
        $session = Connect-GraphAuditSession -Simulation
        ($null -ne $session) | Should Be $true
        ($session.IsSimulated -eq $true) | Should Be $true
        (-not [string]::IsNullOrEmpty($session.TenantId)) | Should Be $true
    }

    It "Detects dormant and unprotected privileged accounts" {
        $session = Connect-GraphAuditSession -Simulation
        $findings = Get-PrivilegedAccountTelemetry -Session $session -InactivityThresholdDays 60
        ($null -ne $findings) | Should Be $true
        ($findings.Count -gt 0) | Should Be $true

        $inactiveRule = $findings | Where-Object { $_.RuleId -eq "ID-AUD-001" }
        ($null -ne $inactiveRule) | Should Be $true

        $mfaRule = $findings | Where-Object { $_.RuleId -eq "ID-AUD-003" }
        ($null -ne $mfaRule) | Should Be $true
    }

    It "Detects high-risk application scopes and secret drifts" {
        $session = Connect-GraphAuditSession -Simulation
        $findings = Test-LeastPrivilegeDrift -Session $session
        ($null -ne $findings) | Should Be $true

        $roleMgmtScope = $findings | Where-Object { $_.Description -match "RoleManagement.ReadWrite.Directory" }
        ($null -ne $roleMgmtScope) | Should Be $true

        $excessiveSecret = $findings | Where-Object { $_.RuleId -eq "ID-AUD-103" }
        ($null -ne $excessiveSecret) | Should Be $true
    }

    It "Detects anomalous audit events and privilege elevations" {
        $session = Connect-GraphAuditSession -Simulation
        $findings = Get-AnomalousAuditEvents -Session $session
        ($null -ne $findings) | Should Be $true

        $elevationEvent = $findings | Where-Object { $_.RuleId -eq "ID-AUD-201" }
        ($null -ne $elevationEvent) | Should Be $true
    }

    It "Orchestrates full audit and computes posture score" {
        $session = Connect-GraphAuditSession -Simulation
        $audit = Invoke-IdentityAudit -Session $session
        ($null -ne $audit) | Should Be $true
        ($audit.TotalFindings -gt 0) | Should Be $true
        ($audit.SeverityBreakdown.CRITICAL -gt 0) | Should Be $true
    }
}
