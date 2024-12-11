function Check-PrivateIPInNamedLocations {
    [CmdletBinding()]
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS019"
        UseCase = "Check for Private IP Addresses in Named Locations"
        WeightedScore = 5
        TechnicalInformation = "This function checks for the presence of private IP addresses in named locations within Azure Active Directory Conditional Access policies. Private IP addresses should not be used in named locations as they can lead to misconfigurations and potential security risks. Attackers can exploit these misconfigurations to bypass security controls and gain unauthorized access."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fulfill later 
        RemedediationSolution = "Review and remove any private IP addresses from named locations in Conditional Access policies. Ensure that only public IP addresses are used to define named locations to maintain proper security boundaries."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        $results = @()

        # Define your resource URI
        $resourceUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"

        # Get named locations
        $namedLocations = Invoke-RestMethod -Uri $resourceUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        # Get Conditional Access policies
        $conditionalAccessPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        # Extract IP addresses from named locations
        $namedLocationIPs = @()
        foreach ($namedLocation in $namedLocations.value) {
            $namedLocationIPs += $namedLocation.ipRanges
        }

        # Check for private IP addresses in named locations
        $privateIPPattern = "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)"
        $privateIPLocations = $namedLocationIPs | Where-Object { $_ -match $privateIPPattern }

        if ($privateIPLocations.Count -gt 0) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Private IP addresses found in named locations: " + ($privateIPLocations | ConvertTo-Json -Compress)
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "No private IP addresses found in named locations."
        }

    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

$accessToken = $args[0]
Check-PrivateIPInNamedLocations -AccessToken $accessToken