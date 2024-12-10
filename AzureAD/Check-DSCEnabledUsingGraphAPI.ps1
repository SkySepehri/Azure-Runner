function Check-DSCEnabledUsingGraphAPI {
    [CmdletBinding()]
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS009"
        UseCase = "Check if Desired State Configuration is Enabled"
        WeightedScore = 5
        TechnicalInformation = "Desired State Configuration (DSC) is a built-in Windows Server feature that uses a central service and the Local Configuration Manager (LCM) to apply configurations automatically. With Azure Automation State Configuration, admins can deploy changes across servers, but attackers could exploit this to deploy malicious configurations or backdoors."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Limit access to Azure Automation and DSC services, enforce least privilege for those managing configurations, regularly audit applied configurations, and monitor for unauthorized changes or suspicious deployments."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        # Define the endpoint to get the list of all service principals
        $graphUrl = "https://graph.microsoft.com/v1.0/servicePrincipals"

        # Invoke the Graph API to get the list of all service principals
        $servicePrincipalsResponse = Invoke-RestMethod -Uri $graphUrl -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        # Filter service principals with appDisplayName equal to 'Microsoft Automation'
        $dscEnabledPrincipals = $servicePrincipalsResponse.value | Where-Object { $_.appDisplayName -eq "Microsoft Automation" }

        if ($dscEnabledPrincipals.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "DSC is enabled for $($dscEnabledPrincipals.Count) service principal(s):`n" + ($dscEnabledPrincipals | ConvertTo-Json -Compress)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Pass: No service principals with DSC enabled found."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

$accessToken = $args[0]
Check-DSCEnabledUsingGraphAPI -AccessToken $accessToken
