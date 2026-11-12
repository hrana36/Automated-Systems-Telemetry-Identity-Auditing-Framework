function Connect-GraphAuditSession {
    <#
    .SYNOPSIS
        Establishes an authenticated session to Microsoft Graph API or initializes a simulation session.
    .PARAMETER TenantId
        Microsoft Entra ID Directory (tenant) ID.
    .PARAMETER ClientId
        Application (client) ID.
    .PARAMETER ClientSecret
        Client secret string for service principal authentication.
    .PARAMETER Simulation
        Switch to run in simulated enterprise mode without live Azure credentials.
    #>
    [CmdletBinding(DefaultParameterSetName = "LiveClientSecret")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "LiveClientSecret")]
        [string]$TenantId,

        [Parameter(Mandatory = $true, ParameterSetName = "LiveClientSecret")]
        [string]$ClientId,

        [Parameter(Mandatory = $true, ParameterSetName = "LiveClientSecret")]
        [string]$ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = "Simulation")]
        [switch]$Simulation
    )

    if ($Simulation) {
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host " [Graph Session] Initialized in SIMULATION / OFFLINE Mode   " -ForegroundColor Cyan
        Write-Host " Tenant: Contoso Global Enterprise (Simulated Testbed)     " -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan

        $session = [PSCustomObject]@{
            IsSimulated = $true
            TenantId    = "72f988bf-86f1-41af-91ab-2d7cd011db47"
            TenantName  = "Contoso Global Enterprise (Simulated)"
            ConnectedAt = (Get-Date).ToUniversalTime()
            AccessToken = "MOCK_BEARER_TOKEN_SIMULATION_MODE"
        }
        $script:CurrentGraphSession = $session
        return $session
    }

    # Live Authentication via OAuth 2.0 Client Credentials Grant
    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }

    Write-Host "[Graph Session] Authenticating with Microsoft Entra ID ($TenantId)..." -ForegroundColor Yellow

    try {
        $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
        $session = [PSCustomObject]@{
            IsSimulated = $false
            TenantId    = $TenantId
            ConnectedAt = (Get-Date).ToUniversalTime()
            AccessToken = $tokenResponse.access_token
            ExpiresIn   = $tokenResponse.expires_in
        }
        $script:CurrentGraphSession = $session
        Write-Host "[Graph Session] Successfully authenticated to Microsoft Graph." -ForegroundColor Green
        return $session
    }
    catch {
        Write-Error "Failed to authenticate to Microsoft Graph: $($_.Exception.Message)"
        throw $_
    }
}
