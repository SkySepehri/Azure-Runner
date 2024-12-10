function Check-TenantCreationPolicies {
    param (
        [Parameter(Mandatory=$true)]
        [string] $AccessToken
    )

    $result = @{
        ItemNumber = "AADS007"
        UseCase = "Misconfigured Tenant Creation Policies"
        WeightedScore = 5
        TechnicalInformation = "Misconfigured tenant creation policies can lead to unauthorized creation of tenants, which attackers can use as an entry point to create malicious environments, deploy applications, or escalate privileges across environments."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Review and enforce strict policies governing tenant creation. Ensure that only trusted administrators have the right to create new tenants, and audit tenant creation events regularly."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    try {
        $graphUri = "https://graph.microsoft.com/v1.0/organization"
        $organization = Invoke-RestMethod -Uri $graphUri -Headers @{ Authorization = "Bearer $AccessToken" }

        $policies = $organization.value[0].resourceAccessPolicies
        $nonAdminTenantCreationAllowed = $policies | Where-Object { $_.resourceType -eq "Microsoft.AzureActiveDirectory/Tenant" -and $_.principalType -eq "User" }

        if ($nonAdminTenantCreationAllowed) {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Non-admin users are allowed to create Azure AD tenants. This poses a security risk as it could lead to unauthorized tenant creation."
        } else {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Only administrators are allowed to create Azure AD tenants, which is the recommended secure configuration."
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
        $result.TechnicalDetails = "An error occurred while checking tenant creation policies: $($result.ErrorMsg)"
    }

    return $result
}

$accessToken = $args[0]
Check-TenantCreationPolicies -AccessToken $accessToken

