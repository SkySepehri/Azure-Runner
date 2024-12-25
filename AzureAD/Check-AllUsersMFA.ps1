# Import required access token script
#. "$PSScriptRoot\Get-MSGraphAccessToken.ps1"

function Get-UserMFAStatus {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    # Define compliance result object
    $complianceResult = @{
        ItemNumber           = "AADS022"
        UseCase             = "Ensure Multi-Factor Authentication (MFA) is enabled for all users (including external)"
        WeightedScore       = 5
        Category            = "Identity and Access Management"
        TechnicalInformation = "Multi-Factor Authentication adds an extra layer of security by requiring additional verification beyond passwords"
        MITREMapping        = "T1078 - Valid Accounts"
        TechnicalDetails    = $null
        RemediationSolution = "Enable MFA for all users (internal and external) through Azure AD Portal or PowerShell"
        Status              = "Unknown"
        ErrorMsg            = $null
    }

    # Define MFA method types to check
    $validMFAMethods = @(
        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
        "#microsoft.graph.phoneAuthenticationMethod",
        "#microsoft.graph.fido2AuthenticationMethod",
        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
        "#microsoft.graph.emailAuthenticationMethod"
    )

    try {
        $headers = @{
            Authorization = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }

        # Initialize separate lists for internal and external users
        $internalUsersWithoutMFA = [System.Collections.ArrayList]::new()
        $externalUsersWithoutMFA = [System.Collections.ArrayList]::new()
        $totalInternalUsers = 0
        $totalExternalUsers = 0
        
        # Query all users
        $nextLink = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,userType&`$top=999"

        # Fetch all users and their MFA status
        while ($nextLink) {
            $usersResponse = Invoke-RestMethod -Uri $nextLink -Headers $headers -Method Get -ErrorAction Stop
            
            foreach ($user in $usersResponse.value) {
                $mfaUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods"
                
                try {
                    $mfaMethods = Invoke-RestMethod -Uri $mfaUrl -Headers $headers -Method Get -ErrorAction Stop
                    
                    $hasMFA = $false
                    foreach ($method in $mfaMethods.value) {
                        if ($method.'@odata.type' -in $validMFAMethods) {
                            $hasMFA = $true
                            break
                        }
                    }

                    # Check if user is external (either Guest type OR has #EXT# in UPN)
                    $isExternal = $user.userType -eq 'Guest' -or $user.userPrincipalName -like '*#EXT#*'

                    if ($isExternal) {
                        $totalExternalUsers++
                        if (-not $hasMFA) {
                            [void]$externalUsersWithoutMFA.Add($user.userPrincipalName)
                        }
                    }
                    else {
                        $totalInternalUsers++
                        if (-not $hasMFA) {
                            [void]$internalUsersWithoutMFA.Add($user.userPrincipalName)
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to fetch MFA methods for user $($user.userPrincipalName): $($_.Exception.Message)"
                    continue
                }
            }

            $nextLink = $usersResponse.'@odata.nextLink'
        }

        # Calculate statistics
        $internalUsersWithMFA = $totalInternalUsers - $internalUsersWithoutMFA.Count
        $externalUsersWithMFA = $totalExternalUsers - $externalUsersWithoutMFA.Count
        
        # Prepare detailed report
        $complianceResult.TechnicalDetails = @"
Internal Users (no #EXT#):
- Total: $totalInternalUsers
- With MFA: $internalUsersWithMFA
- Without MFA: $($internalUsersWithoutMFA.Count)

External Users (Guest or #EXT#):
- Total: $totalExternalUsers
- With MFA: $externalUsersWithMFA
- Without MFA: $($externalUsersWithoutMFA.Count)
"@

        if ($internalUsersWithoutMFA.Count -gt 0) {
            $complianceResult.TechnicalDetails += "`n`nInternal Users lacking MFA: $($internalUsersWithoutMFA -join ', ')"
        }
        if ($externalUsersWithoutMFA.Count -gt 0) {
            $complianceResult.TechnicalDetails += "`n`nExternal Users lacking MFA: $($externalUsersWithoutMFA -join ', ')"
        }

        # Set final status - Fail if either internal or external users are missing MFA
        $complianceResult.Status = if (($internalUsersWithoutMFA.Count -eq 0) -and ($externalUsersWithoutMFA.Count -eq 0)) { 
            "Pass" 
        } else { 
            "Fail" 
        }
    }
    catch {
        $complianceResult.Status = "Error"
        $complianceResult.ErrorMsg = "Failed to check MFA status: $($_.Exception.Message)"
        Write-Error $complianceResult.ErrorMsg
    }

    return $complianceResult | ConvertTo-Json -Depth 10
}

# Example usage:
#$result = Get-UserMFAStatus -AccessToken $AccessToken
#$result | ConvertFrom-Json | Format-List
