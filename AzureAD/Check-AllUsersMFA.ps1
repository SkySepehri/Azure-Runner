function Check-AllUsersMFA {
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS022"
        UseCase = "Ensure Multi-Factor Authentication (MFA) is enabled for all users"
        WeightedScore = 5
        TechnicalInformation = "Multi-Factor Authentication adds an extra layer of security to user accounts by requiring additional verification beyond just a password."
        Category = "Identity and Access Management"
        TechnicalDetails = $null
        RemedediationSolution = "Enable MFA for all users without it. This can be done through the Azure Active Directory portal or by using PowerShell scripts."
        MITREMapping = "T1078 - Valid Accounts"
        Status = $null
        ErrorMsg = $null
    }

    $usersWithoutMFA = @()
    $nextLink = "https://graph.microsoft.com/v1.0/users?`$select=id,userPrincipalName,userType&`$filter=userType eq 'Member'&`$top=999"

    try {
        do {
            $usersResponse = Invoke-RestMethod -Uri $nextLink -Method Get -Headers @{
                Authorization = "Bearer $AccessToken"
            }

            foreach ($user in $usersResponse.value) {
                $mfaInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods" -Method Get -Headers @{
                    Authorization = "Bearer $AccessToken"
                }

                $hasMFA = $mfaInfo.value | Where-Object { $_.'@odata.type' -in @("#microsoft.graph.microsoftAuthenticatorAuthenticationMethod", "#microsoft.graph.phoneAuthenticationMethod", "#microsoft.graph.fido2AuthenticationMethod", "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod", "#microsoft.graph.emailAuthenticationMethod") }

                if (-not $hasMFA) {
                    $usersWithoutMFA += $user.userPrincipalName
                }
            }

            $nextLink = $usersResponse.'@odata.nextLink'
        } while ($nextLink)

        $totalUsers = $usersResponse.'@odata.count'
        $usersWithMFA = $totalUsers - $usersWithoutMFA.Count

        if ($usersWithMFA -lt 0){
            $usersWithMFA = 0
                 
        }

        $result.TechnicalDetails = "Total users: $totalUsers. Users with MFA: $usersWithMFA. Users without MFA: $($usersWithoutMFA.Count)."
        if ($usersWithoutMFA.Count -gt 0) {
            $result.TechnicalDetails += " Users without MFA: $($usersWithoutMFA -join ', ')"
        }
        $result.Status = if ($usersWithoutMFA.Count -eq 0) { "Pass" } else { "Fail" }
    }
    catch {
        $result.Status = "Fail"
        $result.ErrorMsg = "Error checking MFA status: $($_.Exception.Message)"
    }

    return $result
}


$accessToken = $args[0]
Check-AllUsersMFA  -AccessToken $accessToken