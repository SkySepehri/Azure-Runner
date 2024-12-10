function Check-AllowUnverifiedAppPublishers {
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS018"
        UseCase = "Applications from Unverified Publishers in Azure"
        WeightedScore = 9.09
        TechnicalInformation = "Applications from unverified publishers, whose identities aren't validated by Microsoft, may introduce untrusted or malicious software into your environment. Attackers can use these apps to gain unauthorized access, bypass security measures, or extract sensitive data from your Azure environment."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null
        RemedediationSolution = "1. Sign in to the Azure portal as a Global Administrator.
2. Navigate to Azure Active Directory > Enterprise applications > Consent and permissions.
3. Under 'Admin consent settings', configure the following:
   - Set 'Users can request admin consent to apps they are unable to consent to' to 'No'.
   - Ensure 'Selected users can request admin consent to apps they are unable to consent to' is not enabled.
4. Click 'Save' to apply the changes."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Define the Graph API endpoint for user settings
        $userSettingsUri = "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"

        # Get user settings
        $userSettings = Invoke-RestMethod -Uri $userSettingsUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        # Check if users can consent to apps accessing company data on their behalf
        $allowUnverifiedAppPublishers = $userSettings.isEnabled

        if ($allowUnverifiedAppPublishers -eq $false) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Users are not allowed to add apps from unverified publishers."
        } else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Users are allowed to add apps from unverified publishers. This poses a security risk."
        }
    }
    catch {
        $errstr = $_.Exception.Message
        $result.Status = "Error"
        $result.ErrorMsg = "Error checking AllowUnverifiedAppPublishers setting: $errstr"
        Write-Warning $result.ErrorMsg
    }

    return $result
}

$accessToken = $args[0]
Check-AllowUnverifiedAppPublishers -AccessToken $accessToken