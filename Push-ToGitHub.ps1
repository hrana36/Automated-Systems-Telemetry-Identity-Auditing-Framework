<#
.SYNOPSIS
    Pushes this repository to GitHub using a Personal Access Token (PAT) or existing git credentials.
.EXAMPLE
    .\Push-ToGitHub.ps1 -GitHubToken "ghp_xxxxxxxxxxxx"
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$GitHubToken
)

$gitExe = "$env:LOCALAPPDATA\MinGit\cmd\git.exe"
if (-not (Test-Path $gitExe)) {
    $gitExe = (Get-Command git -ErrorAction SilentlyContinue).Source
}

if (-not $GitHubToken) {
    $GitHubToken = Read-Host -Prompt "Enter your GitHub Personal Access Token (PAT with 'repo' scope)" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($GitHubToken)
    $GitHubToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
}

if (-not $GitHubToken) {
    Write-Error "GitHub Token is required to push to GitHub."
    exit 1
}

# 1. Create Repository via GitHub API if it does not exist
$repoName = "Automated-Systems-Telemetry-Identity-Auditing-Framework"
$headers = @{
    "Authorization" = "token $GitHubToken"
    "Accept"        = "application/vnd.github.v3+json"
    "User-Agent"    = "PowerShell-Git-Push"
}

try {
    Write-Host "[GitHub Setup] Checking if repository '$repoName' exists on your GitHub..." -ForegroundColor Cyan
    $existing = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Headers $headers -Method GET
    $found = $existing | Where-Object { $_.name -eq $repoName }

    if (-not $found) {
        Write-Host "[GitHub Setup] Repository not found. Creating 'https://github.com/hrana36/$repoName'..." -ForegroundColor Yellow
        $body = @{
            name        = $repoName
            description = "Automated Systems Telemetry & Identity Auditing Framework for Microsoft Entra ID via Graph REST APIs."
            private     = $false
        } | ConvertTo-Json

        $created = Invoke-RestMethod -Uri "https://api.github.com/user/repos" -Headers $headers -Method POST -Body $body
        Write-Host "[GitHub Setup] Created public repository: $($created.html_url)" -ForegroundColor Green
    }
    else {
        Write-Host "[GitHub Setup] Repository exists: $($found.html_url)" -ForegroundColor Green
    }
}
catch {
    Write-Warning "Could not verify/create repository via API: $($_.Exception.Message). Attempting direct git push..."
}

# 2. Push to GitHub
$authenticatedRemote = "https://hrana36:$GitHubToken@github.com/hrana36/$repoName.git"
Write-Host "[Git] Pushing 'main' branch to GitHub..." -ForegroundColor Cyan
& $gitExe push $authenticatedRemote main --force

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n🎉 Successfully pushed to GitHub!" -ForegroundColor Green
    Write-Host "View your repository at: https://github.com/hrana36/$repoName" -ForegroundColor Green
}
else {
    Write-Error "Git push failed. Please verify your GitHub Token permissions (must include 'repo' scope)."
}
