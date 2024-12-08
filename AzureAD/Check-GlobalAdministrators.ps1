
function Check-GlobalAdministrators {
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS006"
        UseCase = "Azure AD Global Administrators"
        WeightedScore = 5
        TechnicalInformation = "Having too many Global Administrators increases the attack surface, as attackers can target these accounts to gain full control of the tenant. If compromised, a Global Admin account can give attackers unrestricted access to Azure resources, allowing them to escalate privileges, modify security settings, and cause significant harm."
        Category = "Lateral Movement Analysis"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Limit the number of Global Administrators to only what is necessary. Regularly review and audit admin accounts, enforce MFA, and use Privileged Identity Management (PIM) for just-in-time access."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }
    

    # $results = @()

    # Define your resource URI (replace with your specific URI)
    $resourceUri = "https://graph.microsoft.com/v1.0/directoryRoles"

    try {
        $directoryRoles = Invoke-RestMethod -Uri $resourceUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        $globalAdminRole = $directoryRoles.value | Where-Object { $_.displayName -eq "Global Administrator" }

        if (-not $globalAdminRole) {
            $result.Status = "Fail"
            $result.ErrorMsg = "Global Administrator role not found."
            return $result
        }

        $globalAdminMembers = Invoke-RestMethod -Uri "$resourceUri/$($globalAdminRole.id)/members" -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        $globalAdminDetails = $globalAdminMembers.value | ForEach-Object {
            "Display Name: $($_.displayName), UPN: $($_.userPrincipalName)"
        }

        $numGlobalAdmins = $globalAdminMembers.value.Count


        $result.TechnicalDetails = "Number of Global Administrators: $numGlobalAdmins`n`nGlobal Administrators:`n" + ($globalAdminDetails -join "`n")

        Write-Host $result.TechnicalDetails
        # $result.TechnicalDetails = "Number of Global Administrators: $numGlobalAdmins"
        $result.Status = if ($numGlobalAdmins -le 5) { "Pass" } else { "Fail" }
    }
    catch {
        $result.Status = "Fail"
        $result.ErrorMsg = $_.Exception.Message
    }

    return $result
}

$accessToken = $args[0]
Check-GlobalAdministrators -AccessToken $accessToken

