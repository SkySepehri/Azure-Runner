function Detect-AADConnectTakeover {
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS019"
        UseCase = "AAD Connect - Application takeover"
        WeightedScore = 9.09
        TechnicalInformation = "An attacker can use the Microsoft Graph permissions granted to the AAD Connect account, specifically the Entra ID role 'Directory Synchronization Accounts', to take ownership of any enterprise application in Microsoft Entra ID (Azure AD) and add new credentials. These credentials may not be visible in the portal UI and only via Graph requests. The attacker can then sign in using this application and gain its permissions, potentially equivalent to Global Admin."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null
        RemedediationSolution = "Regularly audit and restrict permissions of Directory Synchronization Accounts. Monitor for unusual credential additions to enterprise applications, especially those not visible in the portal UI. Implement least privilege access and use conditional access policies to secure critical accounts and applications."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Get all enterprise applications
        $url = "https://graph.microsoft.com/v1.0/applications"
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }

        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        $applications = $response.value

        $suspiciousApps = @()

        foreach ($app in $applications) {
            # Check for credentials not visible in UI or with auto-generated names
            $credentialUrl = "https://graph.microsoft.com/v1.0/applications/$($app.id)/passwordCredentials"
            $credentialResponse = Invoke-RestMethod -Uri $credentialUrl -Headers $headers -Method Get

            $suspiciousCredentials = $credentialResponse.value | Where-Object { 
                -not $_.displayName -or $_.displayName -match "Password uploaded on"
            }

            $suspiciousCredentialCount = ($suspiciousCredentials | Measure-Object).Count

            write-host  $suspiciousCredentialCount.Count

            if ($suspiciousCredentialCount -gt 0) {
                $suspiciousApps += @{
                    AppId = $app.appId
                    DisplayName = $app.displayName
                    SuspiciousCredentials = $suspiciousCredentialCount
                }
            }

        }

        if ($suspiciousApps.Count -eq 0) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No suspicious credentials detected for enterprise applications."
        }
        else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Suspicious credentials detected for enterprise applications. This could indicate a potential takeover attempt. Findings: $($suspiciousApps | ConvertTo-Json -Compress)"
            write-host $result.TechnicalDetails
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error checking for suspicious credentials: $_"
    }

    return $result
}

$accessToken = $args[0]
Detect-AADConnectTakeover -AccessToken $accessToken