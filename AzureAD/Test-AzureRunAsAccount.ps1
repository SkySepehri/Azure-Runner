# Ensure the Az module is installed
if (-not (Get-Module -ListAvailable -Name Az)) {
    Install-Module -Name Az -Force -AllowClobber
}

# Import the Az module
Import-Module Az

# Import the Az.Resources module specifically
Import-Module Az.Resources

function Test-AzureRunAsAccount {
    [CmdletBinding()]
    param()

    $result = @{
        ItemNumber = "AADS023"
        UseCase = "Test Azure Run As Account"
        WeightedScore = 5
        TechnicalInformation = "This function tests the Azure Run As Account to ensure it is properly configured and has the necessary permissions. Misconfigured Run As Accounts can lead to unauthorized access and potential security risks."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Ensure that the Azure Run As Account is properly configured with the necessary permissions and regularly review and audit its access."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Test the Azure Run As Account
        $runAsAccount = Get-AzADServicePrincipal -DisplayName "AzureRunAsAccount"

        if ($runAsAccount) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: Azure Run As Account is properly configured."
        } else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: Azure Run As Account is not found or not properly configured."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}


$result = Test-AzureRunAsAccount

Write-Output $result | ConvertTo-Json -Depth 10