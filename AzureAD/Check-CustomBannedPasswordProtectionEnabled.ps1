function Check-CustomBannedPasswordProtectionEnabled {
    [CmdletBinding()]
    param (
        [string]$ClientId,
        [string]$TenantId,
        [string]$AccessToken
    )
    $result = @{
        ItemNumber = "AADS001"
        UseCase = "Banned Passwords Protection"
        WeightedScore = 25
        TechnicalInformation = "A banned password policy prevents users from setting weak or commonly used passwords by blacklisting specific terms. Without this protection, attackers can exploit weak passwords through dictionary attacks or credential stuffing, increasing the risk of unauthorized access. Enabling custom banned password protection strengthens security by preventing the use of easily guessable passwords."
        Category = "Account Hygiene"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = "Consider enabling custom banned password protection for enhanced security.
Login: Sign in to the Azure Active Directory portal as a global administrator.
Navigate: Go to Azure Active Directory > Security > Authentication methods.
Select: Click on Password protection.
Toggle: Set Enforce custom list to Yes.
Enter: Add your custom banned passwords in the Custom banned password list.
Save: Click Save to apply the changes."
        MITREMapping = "[MITRE] T1110: Brute Force"
        Status = $null
        ErrorMsg = $null 
    }

    try {

        # Define the resource URI for querying authentication policies
        $authPoliciesUri = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"

        # Retrieve authentication policies
        $authPolicies = Invoke-RestMethod -Uri $authPoliciesUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        Write-Host $authPolicies 
        Write-Host "-----------------"
        # Check if custom banned password protection is enabled
        $bannedPasswordPolicy = $authPolicies.passwordPolicies | Where-Object { $_.name -eq "BannedPasswords" }
        # $bannedPasswordPolicy = $authPolicies.passwordConfiguration.banPasswords


        Write-Host $bannedPasswordPolicy
        

        if ($bannedPasswordPolicy -ne $null -and $bannedPasswordPolicy.enabled) {

            $result.Status = "Pass"
            $result.TechnicalDetails = "Custom banned password protection is enabled. BannedPasswordProtectionEnabled: True"

        } else {
          
            $result.Status = "Fail"
            $result.TechnicalDetails = "Custom banned password protection is not enabled. BannedPasswordProtectionEnabled: False"
        }

        # $results += $result
        Write-Host $result

        return $result
    }
    catch {
        Write-Error "Error checking custom banned password protection: $_"
    }
}

$accessToken = $args[0]
Check-CustomBannedPasswordProtectionEnabled -AccessToken $accessToken