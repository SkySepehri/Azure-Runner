# . "$PSScriptRoot\Get-MSGraphAccessToken.ps1"

function Check-LegacyAuthentication {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS018"
        UseCase = "Exploiting Legacy Authentication"
        WeightedScore = 9.09
        TechnicalInformation = "Legacy authentication protocols (such as POP3, SMTP, IMAP, and MAPI) don't support modern security features like multi-factor authentication and can be more vulnerable to credential attacks."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null
        RemedediationSolution = "To address legacy authentication usage:
1. Identify applications using legacy authentication
2. Update applications to use modern authentication protocols
3. Create Conditional Access policies to block legacy authentication
4. Monitor and communicate with affected users
5. Consider implementing Azure AD Password Protection"
        MITREMapping = "[MITRE] T1110: Brute Force"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Set up request headers
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }

        # Check organization configuration for legacy authentication settings
        $uri = "https://graph.microsoft.com/v1.0/organization"
        $orgConfig = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get -ErrorAction Stop

        # Check authentication methods policy
        $authMethodsUri = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
        $authMethods = Invoke-RestMethod -Uri $authMethodsUri -Headers $headers -Method Get -ErrorAction Stop

        $legacyAuthIndicators = @()

        # Check for basic authentication in Exchange Online
        if ($orgConfig.value.onPremisesSyncEnabled) {
            $legacyAuthIndicators += "Hybrid configuration detected - potential for legacy authentication through on-premises systems"
        }

        # Check for potentially risky authentication methods
        foreach ($method in $authMethods.authenticationMethodConfigurations) {
            if ($method.state -eq "enabled") {
                switch ($method.id) {
                    "email" { $legacyAuthIndicators += "Email authentication enabled - potential legacy protocol usage" }
                    "sms" { $legacyAuthIndicators += "SMS authentication enabled - potential legacy protocol usage" }
                }
            }
        }

        if ($legacyAuthIndicators.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Potential legacy authentication detected:`n" + ($legacyAuthIndicators -join "`n")
        }
        else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No immediate indicators of legacy authentication detected"
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error checking legacy authentication settings: $($_.Exception.Message)"
    }

    return $result
}

$accessToken = $args[0]

$result = Check-LegacyAuthentication -AccessToken $accessToken

Write-Output $result | ConvertTo-Json -Depth 10
