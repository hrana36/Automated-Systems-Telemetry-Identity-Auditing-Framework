function Invoke-GraphRestRequest {
    <#
    .SYNOPSIS
        Executes a REST API call against Microsoft Graph API with pagination and exponential backoff retry.
    .PARAMETER Uri
        The Graph endpoint URI (e.g. https://graph.microsoft.com/v1.0/users).
    .PARAMETER Method
        HTTP method (GET, POST, PATCH, DELETE). Default is GET.
    .PARAMETER AccessToken
        Bearer token for authorization.
    .PARAMETER Body
        Optional payload for POST/PATCH.
    .PARAMETER FollowPages
        If true, automatically traverses @odata.nextLink to retrieve complete directory sets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method = "GET",

        [Parameter(Mandatory = $false)]
        [string]$AccessToken,

        [Parameter(Mandatory = $false)]
        [string]$Body,

        [Parameter(Mandatory = $false)]
        [switch]$FollowPages
    )

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }

    $allResults = [System.Collections.Generic.List[PSObject]]::new()
    $currentUri = $Uri
    $maxRetries = 4

    do {
        $retryCount = 0
        $success = $false
        $response = $null

        while (-not $success -and $retryCount -lt $maxRetries) {
            try {
                $params = @{
                    Uri             = $currentUri
                    Method          = $Method
                    Headers         = $headers
                    UseBasicParsing = $true
                }
                if ($Body -and ($Method -in @("POST", "PATCH"))) {
                    $params["Body"] = $Body
                }

                $rawResponse = Invoke-RestMethod @params
                $success = $true
                $response = $rawResponse
            }
            catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                if ($statusCode -eq 429) {
                    $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                    $waitSec = if ($retryAfter) { [int]$retryAfter } else { [Math]::Pow(2, $retryCount + 1) }
                    Write-Warning "[Graph 429 Throttle] Throttled by Graph API. Backing off for $waitSec seconds..."
                    Start-Sleep -Seconds $waitSec
                    $retryCount++
                }
                else {
                    Write-Error "Graph API request failed [$statusCode]: $($_.Exception.Message)"
                    throw $_
                }
            }
        }

        if ($response.value) {
            foreach ($item in $response.value) {
                $allResults.Add($item)
            }
        }
        else {
            return $response
        }

        if ($FollowPages -and $response.'@odata.nextLink') {
            $currentUri = $response.'@odata.nextLink'
        }
        else {
            $currentUri = $null
        }

    } while ($currentUri)

    return $allResults.ToArray()
}
