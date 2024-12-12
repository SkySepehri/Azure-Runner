function Check-SecurityDefaults {
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS008"
        UseCase = "Security Defaults Enabled or Conditional Access Policies Configured"
        WeightedScore = 5
        TechnicalInformation = "Security defaults or conditional access policies are crucial for protecting against common identity-related attacks. They enforce MFA, block legacy authentication, and implement other security measures."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null
        RemedediationSolution = "Ensure that either security defaults are enabled or appropriate conditional access policies are configured to protect your Azure AD environment."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    $securityDefaultsUri = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    $conditionalAccessUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    try {
        # Check Security Defaults
        $securityDefaultsInfo = Invoke-RestMethod -Uri $securityDefaultsUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        $securityDefaultsEnabled = $securityDefaultsInfo.isEnabled

        # Check Conditional Access Policies
        $conditionalAccessPolicies = Invoke-RestMethod -Uri $conditionalAccessUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        $hasEnabledPolicies = $conditionalAccessPolicies.value | Where-Object { $_.state -eq "enabled" }

        if ($securityDefaultsEnabled) {
            $result.TechnicalDetails = "Security defaults are enabled."
            $result.Status = "Pass"
        } elseif ($hasEnabledPolicies) {
            $result.TechnicalDetails = "Security defaults are disabled, but conditional access policies are configured."
            $result.Status = "Pass"
        } else {
            $result.TechnicalDetails = "Security defaults are disabled and no conditional access policies are configured."
            $result.Status = "Fail"
        }
    }
    catch {
        $result.Status = "Fail"
        $result.ErrorMsg = "Error checking security settings: $($_.Exception.Message)"
        Write-Warning $result.ErrorMsg
    }

    # Convert the result to JSON
    $resultJson = $result | ConvertTo-Json -Depth 9

    # Save the JSON to a file in the same folder as the script
    $jsonFilePath = Join-Path -Path (Get-Location) -ChildPath "SecurityDefaultsResult.dat"
    $resultJson | Set-Content -Path $jsonFilePath -Force

    return $result
}

$accessToken = $args[0]

$result = Check-SecurityDefaults -AccessToken $accessToken

Write-Output $result | ConvertTo-Json -Depth 10