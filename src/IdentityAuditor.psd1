@{
    RootModule           = 'IdentityAuditor.psm1'
    ModuleVersion        = '1.0.0'
    GUID                 = 'b9e71f48-6a52-45e3-9a3b-28751db091ca'
    Author               = 'Md Habibur Rahaman Rana'
    CompanyName          = 'Open Source Community'
    Copyright            = '(c) 2026 Md Habibur Rahaman Rana. All rights reserved.'
    Description          = 'Automated Systems Telemetry & Identity Auditing Framework for Microsoft Entra ID via Graph API and REST endpoints.'
    PowerShellVersion    = '5.1'

    FunctionsToExport    = @(
        'Connect-GraphAuditSession',
        'Invoke-IdentityAudit',
        'Get-PrivilegedAccountTelemetry',
        'Test-LeastPrivilegeDrift',
        'Get-AnomalousAuditEvents',
        'Export-AuditTelemetryReport',
        'Send-AuditAlertNotification'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('Cybersecurity', 'EntraID', 'MicrosoftGraph', 'IdentityGovernance', 'Telemetry', 'Auditing', 'LeastPrivilege')
            ProjectUri = 'https://github.com/hrana36/Automated-Systems-Telemetry-Identity-Auditing-Framework'
            LicenseUri = 'https://opensource.org/licenses/MIT'
        }
    }
}
