function Format-AuditFinding {
    <#
    .SYNOPSIS
        Formats and normalizes an identity security audit finding.
    .PARAMETER RuleId
        Unique identifier for the detection rule (e.g., ID-AUD-001).
    .PARAMETER Severity
        Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.
    .PARAMETER Category
        Audit category: PrivilegedIdentity, DriftDetection, AnomalousLog, PermissionDelegation.
    .PARAMETER Target
        The identity, service principal, or resource affected.
    .PARAMETER Description
        Summary of the detected condition.
    .PARAMETER Remediation
        Recommended action to restore least privilege or mitigate risk.
    .PARAMETER Evidence
        Hashtable or object with detailed telemetry data.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleId,

        [Parameter(Mandatory = $true)]
        [ValidateSet("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Target,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [string]$Remediation,

        [Parameter(Mandatory = $false)]
        [hashtable]$Evidence = @{}
    )

    [PSCustomObject]@{
        FindingId     = [guid]::NewGuid().ToString()
        RuleId        = $RuleId
        TimestampUtc  = (Get-Date).ToUniversalTime().ToString("o")
        Severity      = $Severity
        Category      = $Category
        Target        = $Target
        Description   = $Description
        Remediation   = $Remediation
        Evidence      = $Evidence
    }
}
