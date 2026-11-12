# IdentityAuditor.Tests.ps1 - Automated Unit & Integration Tests

$moduleManifest = Join-Path $PSScriptRoot "..\src\IdentityAuditor.psd1"

Describe "IdentityAuditor Module Integrity" {
    It "Successfully imports the IdentityAuditor module without errors" {
        { Import-Module $moduleManifest -Force } | Should Not Throw
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
        $session | Should Not BeNullOrEmpty
        $session.IsSimulated | Should Be $true
        $session.TenantId | Should Not BeNullOrEmpty
    }

    It "Detects dormant and unprotected privileged accounts" {
        $session = Connect-GraphAuditSession -Simulation
        $findings = Get-PrivilegedAccountTelemetry -Session $session -InactivityThresholdDays 60
        $findings | Should Not BeNullOrEmpty
        $findings.Count | Should BeGreaterThan 0

        $inactiveRule = $findings | Where-Object { $_.RuleId -eq "ID-AUD-001" }
        $inactiveRule | Should Not BeNullOrEmpty

        $mfaRule = $findings | Where-Object { $_.RuleId -eq "ID-AUD-003" }
        $mfaRule | Should Not BeNullOrEmpty
    }

    It "Detects high-risk application scopes and secret drifts" {
        $session = Connect-GraphAuditSession -Simulation
        $findings = Test-LeastPrivilegeDrift -Session $session
        $findings | Should Not BeNullOrEmpty

        $roleMgmtScope = $findings | Where-Object { $_.Description -match "RoleManagement.ReadWrite.Directory" }
        $roleMgmtScope | Should Not BeNullOrEmpty

        $excessiveSecret = $findings | Where-Object { $_.RuleId -eq "ID-AUD-103" }
        $excessiveSecret | Should Not BeNullOrEmpty
    }

    It "Detects anomalous audit events and privilege elevations" {
        $session = Connect-GraphAuditSession -Simulation
        $findings = Get-AnomalousAuditEvents -Session $session
        $findings | Should Not BeNullOrEmpty

        $elevationEvent = $findings | Where-Object { $_.RuleId -eq "ID-AUD-201" }
        $elevationEvent | Should Not BeNullOrEmpty
    }

    It "Orchestrates full audit and computes posture score" {
        $session = Connect-GraphAuditSession -Simulation
        $audit = Invoke-IdentityAudit -Session $session
        $audit | Should Not BeNullOrEmpty
        $audit.TotalFindings | Should BeGreaterThan 0
        $audit.SeverityBreakdown.CRITICAL | Should BeGreaterThan 0
    }
}
