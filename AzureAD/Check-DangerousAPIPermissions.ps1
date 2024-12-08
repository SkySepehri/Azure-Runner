function Check-DangerousAPIPermissions {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $AccessToken
    )

    $result = @{
        ItemNumber = "AADS004"
        UseCase = "Dangerous API Permissions"
        WeightedScore = 5
        TechnicalInformation = "Enterprise Applications and application registrations are crucial components of Entra ID (Azure AD). Managing applications in Entra ID involves granting appropriate permissions to these apps. When an application is granted app permissions, it can access Microsoft Graph endpoints and related data irrespective of user login status. The app can authenticate using secrets or certificates to access this data.

Certain permissions are extensive and potentially risky. If an attacker gains sufficient permissions, they can create a custom app registration, assign additional permissions to it, and use this app as a backdoor to the tenant."
        Category = "Object Privilege & Configuration"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Watch out for the following permissions and remove them if possible.

Application.ReadWrite.All - Grants the application the permission to act as other entities.
AppRoleAssignment.ReadWrite.All - Grants the application the permission to grant additional privileges to itself.
RoleManagement.ReadWrite.Directory - Grants the application the permission to grant additional privileges to itself, other applications, or any user."
        MITREMapping = "[MITRE] T1078: Valid Accounts"
        Status = $null
        ErrorMsg = $null 
    }

    $DangerousAPIPermissions = @{
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8" = "RoleManagement.ReadWrite.Directory -> directly promote yourself to GA"
        "06b708a9-e830-4db3-a914-8e69da51d44f" = "AppRoleAssignment.ReadWrite.All -> grant yourself RoleManagement.ReadWrite.Directory, then promote to GA"
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9" = "Application.ReadWrite.All -> act as another entity e.g. GA"
    }

    $Findings = @()

    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type"  = "application/json"
        }
        $uri = "https://graph.microsoft.com/v1.0/applications"
        $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

        $tenantApplications = $response.value

        foreach ($tenantApplication in $tenantApplications) {
            $servicePrincipalsUri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($tenantApplication.appId)'"
            $servicePrincipalsResponse = Invoke-RestMethod -Method Get -Uri $servicePrincipalsUri -Headers $headers

            $servicePrincipals = $servicePrincipalsResponse.value

            foreach ($servicePrincipal in $servicePrincipals) {
                $roleAssignmentsUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments"
                $roleAssignmentsResponse = Invoke-RestMethod -Method Get -Uri $roleAssignmentsUri -Headers $headers

                $roleAssignments = $roleAssignmentsResponse.value

                foreach ($roleAssignment in $roleAssignments) {
                    if ($roleAssignment.appRoleId -in $DangerousAPIPermissions.Keys) {
                        # App registrations watchlist entry
                        $Findings += [PSCustomObject]@{
                            "objectId"          = $tenantApplication.id
                            "DisplayName"       = $tenantApplication.displayName
                            "GrantedPermission" = $DangerousAPIPermissions[$roleAssignment.appRoleId]
                            "Type"              = "AppRegistration"
                        }
                        $Findings += [PSCustomObject]@{
                            "objectId"          = $servicePrincipal.id
                            "DisplayName"       = $servicePrincipal.displayName
                            "GrantedPermission" = $DangerousAPIPermissions[$roleAssignment.appRoleId]
                            "Type"              = "ServicePrincipal"
                        }
                    }
                }
            }
        }

    #     if ($Findings.Count -eq 0) {
    #         return @{
    #             Description            = "No dangerous API permissions found."
    #             Severity               = "Low"
    #             LikelihoodOfCompromise = "Low"
    #             Findings          = $Findings
    #             FindingSummary          = "No dangerous API permissions detected."
    #             Remediation            = "No action required."
    #             Status                 = "Pass"
    #         }
    #     } else {
    #         $Findings | Out-File -FilePath (Join-Path -Path $settings.reportFolderPath -ChildPath 'DangerousAPIPermissions.txt')
    #         return @{
    #             Description            = "Dangerous API permissions found."
    #             Severity               = "High"
    #             LikelihoodOfCompromise = "High"
    #             Findings                = $Findings
    #             FindingSummary          = "Potentially dangerous API permissions detected. Findings saved in DangerousAPIPermissions.txt"
    #             Remediation            = "Investigate and remove the dangerous API permissions."
    #             Status                 = "Fail"
    #         }
    #     }
    # } catch {
    #     Write-Error "An error occurred: $_"
    #     return @{
    #         Description            = "Error occurred during API call."
    #         Severity               = "High"
    #         LikelihoodOfCompromise = "High"
    #         Findings          = $null
    #         FindingSummary          = "Error occurred during API call."
    #         Remediation            = "Investigate the error and retry."
    #         Status                 = "Error"
    #     }
    # }
    if ($Findings.Count -eq 0) {
        $result.Status = "Pass"
        $result.TechnicalDetails = "No dangerous API permissions detected."
    } else {
        $result.Status = "Fail"
        $technicalDetails = "Potentially dangerous API permissions detected:`n`n"
        foreach ($finding in $Findings) {
            $technicalDetails += "Object ID: $($finding.objectId)`n"
            $technicalDetails += "Display Name: $($finding.DisplayName)`n"
            $technicalDetails += "Granted Permission: $($finding.GrantedPermission)`n"
            $technicalDetails += "Type: $($finding.Type)`n`n"
        }
        $result.TechnicalDetails = $technicalDetails
        Write-Host $result.TechnicalDetails
    }

    return $result
    } catch {
        $result.Status = "Error"
        $result.ErrorMsg = "An error occurred: $_"
        $result.TechnicalDetails = "Error occurred during API call. Investigate the error and retry."
        return $result
    }

}

$accessToken = $args[0]
Check-DangerousAPIPermissions -AccessToken $accessToken
