function Check-LegacyAuthentication {
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "ADS012"
        UseCase = "Exploiting Legacy Authentication"
        WeightedScore = 9.09
        TechnicalInformation = "Legacy authentication refers to older authentication protocols and methods, such as Basic Authentication, which are less secure compared to modern alternatives like OAuth 2.0."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null
        RemedediationSolution = "To address potential legacy authentication vulnerabilities, follow these steps:

1. Sign in to the Azure Portal (https://portal.azure.com) as a Global Administrator.
2. Navigate to Azure Active Directory > Security > Authentication methods.
3. Review the list of enabled authentication methods.
4. For each potentially vulnerable method (email and SMS):
   a. Click on the method to open its settings.
   b. Set the 'Enable' toggle to 'No' to disable the method.
   c. Click 'Save' to apply the changes.
5. Enable more secure authentication methods if not already active:
   a. Enable and configure Microsoft Authenticator app.
   b. Set up FIDO2 security keys.
   c. Configure Windows Hello for Business.
6. After disabling less secure methods, monitor sign-in logs for any failed authentication attempts using legacy protocols.
7. Implement Conditional Access policies to further restrict legacy authentication attempts.

Remember to communicate these changes to your users and provide support for transitioning to more secure authentication methods."
        MITREMapping = "[MITRE] T1110: Brute Force"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Check authentication settings
        $settingsUri = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
        $authSettings = Invoke-RestMethod -Uri $settingsUri -Headers @{Authorization = "Bearer $AccessToken"}

        $legacyAuthPossible = $false
        $enabledMethods = @()

        foreach ($method in $authSettings.authenticationMethodConfigurations) {
            if ($method.state -eq "enabled") {
                $enabledMethods += $method.id
                if ($method.id -in @("email", "sms")) {
                    write-host $method.id
                    $legacyAuthPossible = $true
                }
            }
        }

        if ($legacyAuthPossible) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Potential legacy authentication methods are enabled: $($enabledMethods -join ', '). Email and SMS methods can be used with legacy protocols."
            write-host $result.TechnicalDetails
            
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No legacy authentication methods detected. Enabled methods: $($enabledMethods -join ', ')"
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Failed to check authentication settings: $($_.Exception.Message)"
    }

    return $result
}

$accessToken = $args[0]
Check-LegacyAuthentication -AccessToken $accessToken