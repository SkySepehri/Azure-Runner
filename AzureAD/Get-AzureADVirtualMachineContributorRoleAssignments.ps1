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
        TechnicalDetails = "The function checks for Virtual Machine Contributor role assignments and searches for Run Command events in the subscription activity log over the last 30 days."
        RemedediationSolution = "Regularly review and audit role assignments to ensure that only authorized users and service principals have the Virtual Machine Contributor role. Remove any unnecessary or unauthorized assignments to minimize security risks."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Get role assignments
        $roleAssignments = Get-AzRoleAssignment -RoleDefinitionName "Virtual Machine Contributor" -ExpandPrincipalGroups -ErrorAction Stop

        # Check if any role assignments are found
        if ($roleAssignments.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Virtual Machine Contributor role assignments found: " + ($roleAssignments | ConvertTo-Json -Compress)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No Virtual Machine Contributor role assignments found."
        }

        # Get log events related to Run Command on Virtual Machine
        $logEvents = Get-AzLog -AccessToken $AccessToken -StartTime $startDate -EndTime $endDate -ResourceType "Microsoft.Compute/virtualMachines/extensions" -DetailedOutput

        # Check if any log events are related to Run Command on Virtual Machine
        $runCommandEvents = $logEvents | Where-Object {
            $_.OperationName -eq "Microsoft.Compute/virtualMachines/extensions/runCommand/action"
        }

        # If Run Command events are found, update result object
        if ($runCommandEvents.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails += "`nRun Command events detected for Virtual Machine Contributor role assignments: " + ($runCommandEvents | ConvertTo-Json -Compress)
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

$accessToken = $args[0]

$result = Get-AzureADVirtualMachineContributorRoleAssignments -AccessToken $accessToken
Write-Output $result | ConvertTo-Json -Depth 10