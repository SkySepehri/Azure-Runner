# . "$PSScriptRoot\Get-MSGraphAccessToken.ps1"
function Get-AzureADVirtualMachineContributorRoleAssignments {
    [CmdletBinding()]
    param (
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
        # Get role assignments using Graph API
        $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        $headers = @{ Authorization = "Bearer $AccessToken" }

        Write-Verbose "Fetching role assignments from Microsoft Graph API..."
        $roleAssignments = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

        # Filter for Virtual Machine Contributor assignments
        $virtualMachineContributorAssignments = $roleAssignments.value | Where-Object {
            $_.roleDefinitionId -match "Virtual Machine Contributor"
        }

        if ($virtualMachineContributorAssignments.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Virtual Machine Contributor role assignments found: " + ($virtualMachineContributorAssignments | ConvertTo-Json -Compress)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No Virtual Machine Contributor role assignments found."
        }

        # Simulate checking logs for "Run Command" events (stub for extensibility)
        # For now, log analysis is skipped since it typically requires subscription-level access.
        $result.TechnicalDetails += "`nNo further activity log analysis implemented in this version."

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

# Main script logic
# $accessToken = $args[0]
$result = Get-AzureADVirtualMachineContributorRoleAssignments -AccessToken $accessToken
Write-Output $result | ConvertTo-Json -Depth 10
