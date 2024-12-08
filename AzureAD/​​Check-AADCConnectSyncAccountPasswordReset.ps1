
function Check-AADCConnectSyncAccountPasswordReset {
    [CmdletBinding()]
    param (
        [string]$AccessToken
    )
  
    # $result = @{
    #     Description            = "Check if password reset is enabled for Azure AD Connect sync account."
    #     Severity               = "High"
    #     LikelihoodOfCompromise = "High"
    #     Findings          = $null
    #     FindingSummary          = $null
    #     Score                  = $null
    #     Remediation            = "Review and manage Azure AD Connect sync account settings regularly."
    #     Status                 = $null
    # }

    $result = @{
        ItemNumber = "AADS003"
        UseCase = "AAD Connect - Password reset"
        WeightedScore = 25
        TechnicalInformation = "
When you install Entra ID Connect to sync identities between your on-premises environment and Entra ID, a user named MSOL_[0-9a-f]{12} is created in both directories. This user has broad permissions and is often excluded from security defaults and conditional access policies. If an attacker gains admin access to the Entra ID Connect server, they can extract this user's password and use it to reset passwords or gain access to AAD, particularly if syncing admin accounts with global admin permissions.

In the on-premises environment, the MSOL_ user typically has the ability to reset passwords and read them using DCSync. This access can allow an attacker to obtain the krbtgt password and create golden or silver Kerberos tickets."
        Category = "Account Hygiene"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Treat your Entra ID (Azure AD) Connect server with the same security rigor as a domain controller. Avoid syncing admin accounts between AD and AAD, establish a trust boundary between the directories, and limit the MSOL_ user's capabilities to only necessary organizational units and users. Additionally, follow Microsoft’s hardening recommendations for added security."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }



  
    try {
        $results = @()
  
        $aadConnectUri = "https://graph.microsoft.com/v1.0/servicePrincipals"
  
        $servicePrincipals = Invoke-RestMethod -Uri $aadConnectUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }
  
        $aadConnectSyncAccount = $servicePrincipals.value | Where-Object { $_.displayName -eq "Windows Azure Active Directory Connector" }
  
        if (-not $aadConnectSyncAccount) {
            $result.Status = "Fail"
            $result.TechnicalDetails  = "Fail: Azure AD Connect sync account not found."
        } else {
            $passwordResetEnabled = $aadConnectSyncAccount.appRoles | Where-Object { $_.value -eq "Reset Password" }
            if ($passwordResetEnabled) {
                $result.Status = "Pass"
                $result.TechnicalDetails  = "Pass: Password reset is enabled for Azure AD Connect sync account."
            } else {
                $result.Status = "Fail"
                $result.TechnicalDetails  = "Fail: Password reset is not enabled for Azure AD Connect sync account."
            }
        }
    }
    catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.TechnicalDetails  = "Error: $errstr"
    }
  
    return $result
  }

$accessToken = $args[0]
Check-AADCConnectSyncAccountPasswordReset -AccessToken $accessToken

