function Check-AzureADRoleChanges {
    [CmdletBinding()]
    param (
        [string]$AccessToken
    )

    # Define an array of roles to check for
    $rolesToCheck = @("Global Administrator", "Company Administrator", "Privileged Authentication Administrator", "Privileged Role Administrator")

    $result = @{
        ItemNumber = "AADS005"
        UseCase = "Azure AD Roles"
        WeightedScore = 5
        TechnicalInformation = "Assigning inappropriate Entra ID (Azure AD) roles to a user or application can create a pathway to global admin access. Specifically, the Privileged Authentication Administrator role essentially grants Global Admin-level permissions, as it allows resetting the password of any Global Admin, modifying MFA settings, and potentially taking over their account.

The Privileged Role Administrator role allows its holder to assign additional Entra ID (Azure AD) roles to any user, including the Global Administrator role. This role also extends to API permissions, enabling the user to grant consent for any permission to any application."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Carefully manage and audit role assignments in Azure AD. Limit high-privilege roles to trusted personnel and regularly review role assignments and API permissions to prevent unauthorized access. Implement strong role-based access controls and monitor for any suspicious changes."
        MITREMapping = "[MITRE] T1098: Account Manipulation"
        Status = $null
        ErrorMsg = $null 
    }

    

    # Get Azure AD audit logs
    # $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
    $uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
    $auditLogs = @()

    do {
        try {
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers @{Authorization = "Bearer $AccessToken"}
            $auditLogs += $response.value
            $uri = $response.'@odata.nextLink'
        }
        catch {
            $result.ErrorMsg = "Failed to retrieve audit logs: $($_.Exception.Message)"
            $result.Status = "Error"
            return $result
        }
    } while ($uri)
    # $auditLogs = Invoke-RestMethod -Method Get -Uri $uri -Headers @{Authorization = "Bearer $AccessToken"}

    # Filter audit logs for potential role changes based on activity display name
    # $potentialRoleChanges = $auditLogs.value | Where-Object { $_.activityDisplayName -match "Add member to role|Remove member from role" }

    $potentialRoleChanges = $auditLogs | Where-Object { 
        $_.activityDisplayName -match "Add member to role|Remove member from role|Add eligible member to role|Remove eligible member from role|Update role" -and
        $_.category -eq "RoleManagement"
    }
    
    $roleChanges = @()

    # foreach ($roleChange in $potentialRoleChanges) {
    #     foreach ($resource in $roleChange.targetResources) {
    #         foreach ($role in $rolesToCheck) {
    #             if ($resource.displayName -eq $role) {
    #                 $roleChanges += "Activity: $($roleChange.activityDisplayName), Role: $role, Initiator: $($roleChange.initiatedBy.user.displayName), DateTime: $($roleChange.activityDateTime)"
    #             }
    #         }
    #     }
    # }

    $roleChanges = @()

    foreach ($roleChange in $potentialRoleChanges) {
        $targetResources = $roleChange.targetResources
        #write-host $targetResources
        if ($targetResources -and $targetResources.Count -gt 0 -and $modifiedProperties) {
            $roleName = ($modifiedProperties | Where-Object { $_.displayName -eq "Role.DisplayName" }).newValue
            write-host abc
            if ($roleName) {
                $roleName = $roleName.Trim('"')
                if ($rolesToCheck -contains $roleName) {
                #write-host $roleName
                    $roleChanges += [PSCustomObject]@{
                        Activity = $roleChange.activityDisplayName
                        Role = $roleName
                        Initiator = $roleChange.initiatedBy.user.userPrincipalName
                        DateTime = $roleChange.activityDateTime
                    }
                }
            }
        }        
    }


   # write-host $roleChange
    



    # Set TechnicalDetails
    # if ($roleChanges) {
    #     $result.TechnicalDetails = "No role changes detected for specified roles (Global Administrator, Company Administrator, Privileged Authentication Administrator, Privileged Role Administrator)."
    #     $result.Status = "Pass"
    # } else {
    #     $result.TechnicalDetails = "Role changes detected for specified roles:n" + ($roleChanges -join "n")
    #     $result.Status = "Fail"
    # }

    if ($roleChanges) {
        $result.TechnicalDetails = "Role changes detected for specified roles:n" + ($roleChanges | ForEach-Object { "$($_.Activity), Role: $($_.Role), Initiator: $($_.Initiator), DateTime: $($_.DateTime)" } -join "n")
        $result.Status = "Fail"
    } else {
        $result.TechnicalDetails = "No role changes detected for specified roles (Global Administrator, Company Administrator, Privileged Authentication Administrator, Privileged Role Administrator)."
        $result.Status = "Pass"
    }
    

    write-host $result.TechnicalDetails

    return $result
}

$accessToken = $args[0]
Check-AzureADRoleChanges -AccessToken $accessToken