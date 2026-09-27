<#
.SYNOPSIS
    Disables an Entra ID user account. Called by the agent ONLY after human approval.
.NOTES
    Uses the OAuth2 token method (not -ClientSecretCredential) and pins the Graph module
    version, per lab convention. Reads app credentials from environment variables set by
    the Python host so no secrets are hard-coded here.
#>
param(
    [Parameter(Mandatory = $true)][string]$Upn,
    [Parameter(Mandatory = $true)][string]$Reason
)

$ErrorActionPreference = 'Stop'

$tenantId = $env:TENANT_ID
$clientId = $env:CLIENT_ID
$clientSecret = $env:CLIENT_SECRET

if (-not ($tenantId -and $clientId -and $clientSecret)) {
    throw "TENANT_ID / CLIENT_ID / CLIENT_SECRET must be set in the environment."
}

Import-Module Microsoft.Graph.Authentication -RequiredVersion 2.25.0
Import-Module Microsoft.Graph.Users -RequiredVersion 2.25.0

# --- OAuth2 token method (client credentials) ---
$body = @{
    client_id     = $clientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}
$tokenResponse = Invoke-RestMethod -Method Post `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" -Body $body

$secureToken = ConvertTo-SecureString $tokenResponse.access_token -AsPlainText -Force
Connect-MgGraph -AccessToken $secureToken | Out-Null

# --- The gated action ---
Update-MgUser -UserId $Upn -AccountEnabled:$false

Write-Output "DISABLED: $Upn  (reason: $Reason)"
Disconnect-MgGraph | Out-Null
