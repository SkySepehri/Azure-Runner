function Check-PrivilegedRolesForGuestAccounts {
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS012"
        UseCase = "Privileged Roles for Guest Account"
        WeightedScore = 5
        TechnicalInformation = "Privileged roles in Active Directory provide elevated access and control over resources. Assigning such roles to guest accounts can pose a significant security risk, as these external or temporary accounts may not adhere to the same security standards as internal users. Attackers exploiting these roles could gain unauthorized access to sensitive systems and data, potentially compromising the entire environment."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null
        RemediationSolution = "To address the issue of privileged roles assigned to guest accounts:

1. Review all guest accounts with privileged roles identified in the audit.
2. For each guest account:
   a. Evaluate the business need for the privileged role assignment.
   b. If the privileged access is not required, remove the guest account from the role:
      - Go to Azure AD Admin Center > Roles and administrators
      - Select the specific role
      - Find the guest account and remove it from the role
   c. If privileged access is necessary, consider the following alternatives:
      - Create a separate internal account for the user with appropriate controls
      - Implement Privileged Identity Management (PIM) for just-in-time, time-bound access
      - Enable multi-factor authentication and conditional access policies for the account
3. Implement a regular review process for privileged role assignments, especially for guest accounts.
4. Establish and enforce a policy regarding privileged access for external users.
5. Set up alerts for any new privileged role assignments to guest accounts.

Remember to document all changes and decisions made during this remediation process."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    $resourceUri = "https://graph.microsoft.com/v1.0/directoryRoles"

    try {
        $directoryRoles = Invoke-RestMethod -Uri $resourceUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        $guestAccountsWithPrivilegedRoles = @()

        foreach ($role in $directoryRoles.value) {
            $membersUri = "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=userPrincipalName,userType"
            $members = Invoke-RestMethod -Uri $membersUri -Method Get -Headers @{
                Authorization = "Bearer $AccessToken"
            }

            $guestMembers = $members.value | Where-Object { $_.userType -eq "Guest" }
            if ($guestMembers) {
                foreach ($guest in $guestMembers) {
                    $guestAccountsWithPrivilegedRoles += [PSCustomObject]@{
                        RoleName = $role.displayName
                        GuestUserPrincipalName = $guest.userPrincipalName
                    }
                }
            }
        }

        $result.TechnicalDetails = if ($guestAccountsWithPrivilegedRoles.Count -gt 0) {
            "Guest accounts with privileged roles:`n" + ($guestAccountsWithPrivilegedRoles | Format-Table -AutoSize | Out-String)
        } else {
            "No guest accounts found with privileged roles assigned."
        }

        $result.Status = if ($guestAccountsWithPrivilegedRoles.Count -gt 0) { "Fail" } else { "Pass" }
        write-host $result.TechnicalDetails
    }
    catch {
        $result.ErrorMsg = "Error checking privileged roles for guest accounts: $($_.Exception.Message)"
        $result.Status = "Error"
        Write-Warning $result.ErrorMsg
    }

    $jsonFilePath = Join-Path -Path (Get-Location) -ChildPath "PrivilegedRolesForGuestAccountsResult.dat"
    $result | ConvertTo-Json -Depth 4 | Set-Content -Path $jsonFilePath -Force

    return $result
}

$accessToken = $args[0]

$result = Check-PrivilegedRolesForGuestAccounts -AccessToken $accessToken

Write-Output $result | ConvertTo-Json -Depth 10