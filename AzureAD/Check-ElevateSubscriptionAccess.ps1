function Check-ElevateSubscriptionAccess {
    param (
        [string]$tenantId,
        [string]$clientId,
        [string]$clientSecret
    )

    $result = @{
        ItemNumber = "AADS011"
        UseCase = "Elevate Azure Subscription Access"
        WeightedScore = 5
        TechnicalInformation = "An Azure subscription is a logical container in Microsoft Azure used to manage resources like virtual machines, databases, and storage. It groups resources for billing, access control, and organization. Each subscription is associated with one or more Azure Active Directory (Entra ID) tenants and can have role-based access controls (Azure RBAC) to manage permissions.

Elevate Azure Subscription Access allows attackers with elevated roles to gain significant permissions in Azure. By enabling Access management for Azure resources in Entra ID, the attacker can assign roles and permissions across all subscriptions or management groups, potentially persisting malicious access."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null
        RemedediationSolution = "To mitigate Elevate Azure Subscription Access risks, limit assignments of elevated roles, use Privileged Identity Management (PIM) for just-in-time access, enforce MFA, regularly audit role assignments, disable Access management for Azure resources if unnecessary, and apply least privilege and Conditional Access policies.

Here are concise instructions to mitigate the risks of elevated Azure subscription access by implementing best practices:
Enable Privileged Identity Management (PIM):
Navigate: Go to Azure Active Directory > Privileged Identity Management.
Activate PIM: Click on Azure AD roles and select Manage roles.
Assign Eligible Roles: For users needing elevated access, select their role (e.g., Global Administrator) and set them as Eligible.
Set Activation Duration: Specify the duration for which the role can be activated (e.g., 1 hour).
Enforce Multi-Factor Authentication (MFA):
Navigate: Go to Azure Active Directory > Security > Conditional Access.
Create Policy: Click New policy and set conditions to require MFA for elevated roles.
Enable Policy: Ensure the policy is enabled and apply it to the appropriate users.
Disable Access Management for Azure Resources if Unnecessary:
Navigate: Go to Azure Active Directory > Roles and administrators.
Select: Click on Access management for Azure resources.
Disable: If not needed, turn off this feature to limit access."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Get an access token
        $body = @{
            grant_type    = "client_credentials"
            scope         = "https://graph.microsoft.com/.default"
            client_id     = $clientId
            client_secret = $clientSecret
        }

        $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        $accessToken = $tokenResponse.access_token

        # Define the list of elevated roles to check
        $elevatedRoles = @{
            "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
            "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Access Administrator"
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" = "Owner"
            "b24988ac-6180-42a0-ab88-20f7382dd24c" = "Contributor"
            "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
        }

        # Check for elevated subscription access using Microsoft Graph API
        $graphUrl = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        $headers = @{
            Authorization = "Bearer $accessToken"
        }

        $roleAssignmentsResponse = Invoke-RestMethod -Uri $graphUrl -Method Get -Headers $headers
        $elevationUsers = $roleAssignmentsResponse.value | Where-Object { $elevatedRoles.Keys -contains $_.roleDefinitionId }

        # Get user details for elevated roles
        $elevationUsersDetails = @()
        foreach ($user in $elevationUsers) {
            $userDetails = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($user.principalId)" -Method Get -Headers $headers
            $elevationUsersDetails += [PSCustomObject]@{
                DisplayName = $userDetails.displayName
                UserPrincipalName = $userDetails.userPrincipalName
                RoleName = $elevatedRoles[$user.roleDefinitionId]
            }
        }

        $result.TechnicalDetails = @{
            ElevationUsers = $elevationUsersDetails
        }

        if ($elevationUsersDetails.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Elevated subscription access found: " + ($elevationUsersDetails | ConvertTo-Json -Compress)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No elevated subscription access found."
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error occurred while fetching users with elevation access. Error: $($_.Exception.Message)"
    }

    return $result
}

$accessToken = $args[0]
$tenantId = $args[1]
$clientID = $args[2]
$clientSecret = $args[3]

Check-ElevateSubscriptionAccess -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret
