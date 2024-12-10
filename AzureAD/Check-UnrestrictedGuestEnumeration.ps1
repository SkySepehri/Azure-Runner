function Check-UnrestrictedGuestEnumeration {
    [CmdletBinding()]
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS021"
        UseCase = "Exploiting Unrestricted Guest Access in Azure AD"
        WeightedScore = 20
        TechnicalInformation = "Unrestricted guest access can be exploited by attackers to perform reconnaissance, enumerating users and groups within the tenant. This information can facilitate further attacks like privilege escalation or lateral movement, compromising the security of the Azure AD environment."
        Category = "Lateral Movement Analyst"
        TechnicalDetails = $null
        RemedediationSolution = "1. Review guest user access:
   - Audit all guest users in your Azure AD tenant.
   - Identify and document the purpose of each guest account.

2. Implement least privilege principle:
   - Remove unnecessary group memberships and permissions from guest accounts.
   - Ensure guest users have access only to resources they absolutely need.

3. Configure Azure AD external collaboration settings:
   - Go to Azure AD > External Identities > External collaboration settings.
   - Set Guest user access restrictions to Limited access or a more restrictive option.

4. Enable Conditional Access policies for guest users:
   - Create policies that require multi-factor authentication for guest access.
   - Implement device compliance checks for guest users if applicable.

5. Regularly monitor and review guest user activities:
   - Set up Azure AD audit logs to track guest user actions.
   - Implement automated alerts for suspicious guest user activities.
"
        MITREMapping = "[MITRE] T1087: Account Discovery"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        $guestUsersUri = "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'"
        $guestUsers = Invoke-RestMethod -Uri $guestUsersUri -Method Get -Headers @{Authorization = "Bearer $AccessToken"}

        $unrestrictedGuests = @()

        foreach ($guestUser in $guestUsers.value) {
            $permissionsUri = "https://graph.microsoft.com/v1.0/users/$($guestUser.id)/memberOf"
            $guestPermissions = Invoke-RestMethod -Uri $permissionsUri -Method Get -Headers @{Authorization = "Bearer $AccessToken"}
            
            if ($guestPermissions.value.Count -gt 0) {
                $unrestrictedGuests += $guestUser
            }
        }

        if ($unrestrictedGuests.Count -gt 0) {
            $result.Status = "Fail"
            $guestUserNames = ($unrestrictedGuests | ForEach-Object { $_.userPrincipalName }) -join ', '
            $result.TechnicalDetails = "Found $($unrestrictedGuests.Count) guest users with potentially dangerous permissions. Guest users: $guestUserNames"
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No guest users with potentially dangerous permissions found."
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error checking unrestricted guest enumeration: $_"
    }

    return $result
}

$accessToken = $args[0]
Check-UnrestrictedGuestEnumeration -AccessToken $accessToken