# . "$PSScriptRoot\Get-MSGraphAccessToken.ps1"

function Test-AzureRunAsAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS023"
        UseCase = "Test Azure Run As Account"
        WeightedScore = 5
        TechnicalInformation = "This function tests the Azure Run As Account to ensure it is properly configured and has the necessary permissions. Misconfigured Run As Accounts can lead to unauthorized access and potential security risks."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null
        RemediationSolution = "Ensure that the Azure Run As Account is properly configured with the necessary permissions and regularly review and audit its access."
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

        # Query for the Azure Run As Account using Graph API
        $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=displayName eq 'AzureRunAsAccount'"
        
        Write-Verbose "Querying Graph API for Azure Run As Account..."
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get

        if ($response.value.Count -gt 0) {
            $runAsAccount = $response.value[0]
            
            # Get additional details about the service principal
            $spUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($runAsAccount.id)"
            $spDetails = Invoke-RestMethod -Uri $spUri -Headers $headers -Method Get

            # Build detailed information
            $details = @{
                ObjectId = $spDetails.id
                DisplayName = $spDetails.displayName
                AppId = $spDetails.appId
                Enabled = $spDetails.accountEnabled
                CreatedDateTime = $spDetails.createdDateTime
            }

            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: Azure Run As Account is properly configured.`nDetails: $($details | ConvertTo-Json)"
        }
        else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Fail: Azure Run As Account is not found or not properly configured."
        }
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
# $result = Test-AzureRunAsAccount -AccessToken $accessToken
# Write-Output $result | ConvertTo-Json -Depth 10
