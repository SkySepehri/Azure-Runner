#
function Check-InactiveUsersOrDevices {
    [CmdletBinding()]
    param (
        [string]$AccessToken
    )

    $results = @()

    # Define your resource URIs for users and devices
    $userResourceUri = "https://graph.microsoft.com/v1.0/users"
    $deviceResourceUri = "https://graph.microsoft.com/v1.0/devices"

    try {
        $inactiveUsersResponse = Invoke-RestMethod -Uri $userResourceUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }
        $inactiveUsers = $inactiveUsersResponse.value | Where-Object { 
            if ($_.signInSessionsValidFromDateTime) {
                [datetime]$_.signInSessionsValidFromDateTime -lt (Get-Date).AddDays(-30)
            } else {
                $true
            }
        }

        $inactiveDevicesResponse = Invoke-RestMethod -Uri $deviceResourceUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }
        $inactiveDevices = $inactiveDevicesResponse.value | Where-Object { 
            if ($_.approximateLastSignInDateTime) {
                [datetime]$_.approximateLastSignInDateTime -lt (Get-Date).AddDays(-30)
            } else {
                $true
            }
        }

        if ($inactiveUsers.Count -gt 0) {
            $result = @{
                ItemNumber = "AADS003"
                UseCase = "Identify Inactive Users or Devices in Active Directory"
                WeightedScore = 3
                TechnicalInformation = "This use case identifies inactive user accounts or devices in Active Directory. Inactive accounts or devices can pose a security risk as they may be exploited by attackers to gain unauthorized access to the network. Regularly identifying and managing inactive accounts helps reduce the attack surface and improve overall security."
                Category = "Account Hygiene"
                TechnicalDetails = $inactiveUsers | Select-Object DisplayName, UserPrincipalName, signInSessionsValidFromDateTime
                RemedediationSolution = "Regularly review and disable or remove inactive user accounts and devices to minimize security risks. Ensure that only active and necessary accounts and devices are maintained in Active Directory."
                MITREMapping = "[MITRE] T1078: Valid Accounts"
                Status = "Fail"
                ErrorMsg = $null
            }
            $results += $result
        }

        if ($inactiveDevices.Count -gt 0) {
            $result = @{
                ItemNumber = "AADS003"
                UseCase = "Identify Inactive Users or Devices in Active Directory"
                WeightedScore = 3
                TechnicalInformation = "This use case identifies inactive user accounts or devices in Active Directory. Inactive accounts or devices can pose a security risk as they may be exploited by attackers to gain unauthorized access to the network. Regularly identifying and managing inactive accounts helps reduce the attack surface and improve overall security."
                Category = "Account Hygiene"
                TechnicalDetails = $inactiveUsers | Select-Object DisplayName, UserPrincipalName, signInSessionsValidFromDateTime
                RemedediationSolution = "Regularly review and disable or remove inactive user accounts and devices to minimize security risks. Ensure that only active and necessary accounts and devices are maintained in Active Directory."
                MITREMapping = "[MITRE] T1078: Valid Accounts"
                Status = "Fail"
                ErrorMsg = $null
            }
            $results += $result
        }

        if ($results.Count -eq 0) {
            $result = @{
                ItemNumber = "AADS003"
                UseCase = "Identify Inactive Users or Devices in Active Directory"
                WeightedScore = 3
                TechnicalInformation = "This use case identifies inactive user accounts or devices in Active Directory. Inactive accounts or devices can pose a security risk as they may be exploited by attackers to gain unauthorized access to the network. Regularly identifying and managing inactive accounts helps reduce the attack surface and improve overall security."
                Category = "Account Hygiene"
                TechnicalDetails = $null
                RemedediationSolution = "Regularly review and disable or remove inactive user accounts and devices to minimize security risks. Ensure that only active and necessary accounts and devices are maintained in Active Directory."
                MITREMapping = "[MITRE] T1078: Valid Accounts"
                Status = "Pass"
                ErrorMsg = $null
            }
            $results += $result
        }

    } catch {
        $errstr = $_.exception.message
        $result = @{
            ItemNumber = "AADS003"
            UseCase = "Error checking inactive users or devices."
            WeightedScore = 3
            TechnicalInformation = "An error occurred while checking for inactive users or devices in Azure AD."
            Category = "Account and Device Management"
            TechnicalDetails = $null
            RemedediationSolution = "Investigate and resolve the issue."
            MITREMapping = "[MITRE] T1078: Valid Accounts"
            Status = "Fail"
            ErrorMsg = $errstr
        }
        $results += $result
    }

    return $results
}

$accessToken = $args[0]

$result = Check-InactiveUsersOrDevices -AccessToken $accessToken

Write-Output $result | ConvertTo-Json -Depth 10