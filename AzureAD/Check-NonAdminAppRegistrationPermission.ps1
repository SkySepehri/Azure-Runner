function Check-NonAdminAppRegistrationPermission {
    param (
        [Parameter(Mandatory=$true)]
        [string] $AccessToken
    )

    $result = @{
        ItemNumber = "AADS015"
        UseCase = "Allowing Non-Admin Users to Register Custom Applications"
        WeightedScore = 9.09
        TechnicalInformation = "Allowing non-admin users to register custom applications opens the possibility for attackers to create malicious app registrations that request high-level permissions. This could lead to unauthorized access, privilege escalation, and broader attacks across the Azure AD environment."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null
        RemedediationSolution = "Limit app registration permissions to administrators and audit the registration of applications in your Azure AD environment to mitigate potential abuse."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        $graphUri = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        $policy = Invoke-RestMethod -Uri $graphUri -Headers @{ Authorization = "Bearer $AccessToken" }
        $defaultUserRolePermissions = $policy.defaultUserRolePermissions

        if ($defaultUserRolePermissions.allowedToCreateApps) {
            $result.Status = "Fail"
            
            # Get all users
            $usersUri = "https://graph.microsoft.com/v1.0/users?`$select=userPrincipalName,userType"
            $users = Invoke-RestMethod -Uri $usersUri -Headers @{ Authorization = "Bearer $AccessToken" }
            
            $nonAdminUsers = $users.value | Where-Object { $_.userType -eq 'Member' }
            $nonAdminUsersList = $nonAdminUsers.userPrincipalName -join ', '
            
            $result.TechnicalDetails = "Non-admin users are allowed to register custom applications. The following users have this ability: $nonAdminUsersList"
            write-host $result.TechnicalDetails
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Non-admin users are not allowed to register custom applications. This setting is disabled in the default user role permissions."
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error checking non-admin app registration permission: $($_.Exception.Message)"
    }

    return $result 
}

$accessToken = $args[0]
Check-NonAdminAppRegistrationPermission -AccessToken $accessToken