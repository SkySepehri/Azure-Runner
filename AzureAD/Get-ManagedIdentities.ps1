function Get-ManagedIdentities {
    param (
        [string]$tenantId,
        [string]$clientId,
        [string]$clientSecret
    )

    $result = @{
        ItemNumber = "AADS010"
        UseCase = "Retrieve Managed Identities"
        WeightedScore = 5
        TechnicalInformation = "Managed Identities allow resources like virtual machines to access other resources without handling credentials. However, if a managed identity is granted excessive permissions, an attacker could exploit it to control resources. For example, a virtual machine with a managed identity that has contributor access to a subscription can potentially take over all resources within that subscription and move laterally to other virtual machines."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Follow the principle of least privilege by assigning minimal permissions to managed identities, regularly audit access, and monitor for suspicious activity. Avoid granting overly broad roles like contributor at the subscription level."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Get an access token
        $body = @{
            grant_type    = "client_credentials"
            scope         = "https://graph.microsoft.com/.default"
            client_id     = $clientId
            client_secret = $clientSecret
        }

        $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        $accessToken = $tokenResponse.access_token

        # Get managed identities using Microsoft Graph API
        $graphUrl = "https://graph.microsoft.com/v1.0/servicePrincipals"
        $headers = @{
            Authorization = "Bearer $accessToken"
        }

        $managedIdentitiesResponse = Invoke-RestMethod -Uri $graphUrl -Method Get -Headers $headers
        $managedIdentities = $managedIdentitiesResponse.value | Where-Object { $_.tags -contains "WindowsAzureActiveDirectoryManagedIdentity" }

        if ($managedIdentities.Count -gt 0) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Managed identities found: " + ($managedIdentities | ConvertTo-Json -Compress)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No managed identities found."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

$accessToken = $args[0]
$tenantId = $args[1]
$clientID = $args[2]
$clientSecret = $args[3]

Get-ManagedIdentities -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret