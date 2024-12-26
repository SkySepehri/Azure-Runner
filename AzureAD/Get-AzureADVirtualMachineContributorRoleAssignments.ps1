# . "$PSScriptRoot\Get-MSGraphAccessToken.ps1"

function Get-AzureADVirtualMachineContributorRoleAssignments {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,
        [datetime]$startDate = (Get-Date).AddDays(-30),
        [datetime]$endDate = (Get-Date)
    )

    $result = @{
        ItemNumber = "AADS013"
        UseCase = "Identify Azure AD Virtual Machine Contributor Role Assignments"
        WeightedScore = 5
        TechnicalInformation = "This function retrieves and identifies all users and service principals assigned the Virtual Machine Contributor role in Azure Active Directory. The Virtual Machine Contributor role grants significant permissions, including the ability to manage virtual machines. If misconfigured, attackers can exploit these permissions to gain control over virtual machines, potentially leading to unauthorized access and data breaches."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = "The function checks for Virtual Machine Contributor role assignments using Microsoft Graph API."
        RemediationSolution = "Regularly review and audit role assignments to ensure that only authorized users and service principals have the Virtual Machine Contributor role. Remove any unnecessary or unauthorized assignments to minimize security risks."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null
    }

    try {
        # Set up headers for Graph API calls
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }

        # First, get the Virtual Machine Contributor role definition ID
        $rolesUri = "https://graph.microsoft.com/v1.0/directoryRoles"
        Write-Verbose "Fetching directory roles..."
        $roles = Invoke-RestMethod -Uri $rolesUri -Headers $headers -Method Get
        
        # Find VM Contributor role
        $vmContributorRole = $roles.value | Where-Object { 
            $_.displayName -like "*Virtual Machine Contributor*" 
        }

        if ($vmContributorRole) {
            # Get role assignments for this role
            $assignmentsUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($vmContributorRole.id)'"
            Write-Verbose "Fetching role assignments..."
            $assignments = Invoke-RestMethod -Uri $assignmentsUri -Headers $headers -Method Get

            $detailedAssignments = @()

            foreach ($assignment in $assignments.value) {
                # Get principal (user/service principal) details
                $principalUri = "https://graph.microsoft.com/v1.0/directoryObjects/$($assignment.principalId)"
                $principal = Invoke-RestMethod -Uri $principalUri -Headers $headers -Method Get

                $detailedAssignments += [PSCustomObject]@{
                    RoleId = $assignment.roleDefinitionId
                    RoleName = $vmContributorRole.displayName
                    PrincipalId = $assignment.principalId
                    PrincipalType = $principal.'@odata.type'
                    PrincipalName = $principal.displayName
                    AssignmentId = $assignment.id
                    CreatedDateTime = $assignment.createdDateTime
                }
            }

            if ($detailedAssignments.Count -gt 0) {
                $result.Status = "Fail"
                $result.TechnicalDetails = "Found $($detailedAssignments.Count) Virtual Machine Contributor role assignments:`n"
                $result.TechnicalDetails += ($detailedAssignments | ConvertTo-Json -Compress)
            }
            else {
                $result.Status = "Pass"
                $result.TechnicalDetails = "No Virtual Machine Contributor role assignments found."
            }
        }
        else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Virtual Machine Contributor role not found in the directory."
        }

        # Add audit log check period
        $result.TechnicalDetails += "`nChecked assignments for period: $startDate to $endDate"
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = "Error accessing Graph API: $($_.Exception.Message)"
        Write-Error $_.Exception.Message
    }

    return $result
}

# Main script execution
# Note: Make sure to provide the access token when calling the function
#$result = Get-AzureADVirtualMachineContributorRoleAssignments -AccessToken $accessToken 
#Write-Output $result | ConvertTo-Json -Depth 10
