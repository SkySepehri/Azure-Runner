
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
        $inactiveUsers = Invoke-RestMethod -Uri $userResourceUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        } | Where-Object { $_.lastActivityDateTime -eq $null -or (Get-Date) - $_.lastActivityDateTime -ge [TimeSpan]::FromDays(90) }
  
        $inactiveDevices = Invoke-RestMethod -Uri $deviceResourceUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        } | Where-Object { $_.lastActivityDateTime -eq $null -or (Get-Date) - $_.lastActivityDateTime -ge [TimeSpan]::FromDays(90) }
  
        # Combine results
        if ($inactiveUsers -or $inactiveDevices) {
            $combinedResult = @{
                Description            = "Check if any users or devices have been inactive for at least 90 days."
                Severity               = "Informational"
                LikelihoodOfCompromise = "Low"
                Findings          = @($inactiveUsers, $inactiveDevices)
                FindingSummary          = "Found "
                Score                  = $null
                Remediation            = "Review and manage user and device activity and access regularly."
                Status                 = "Fail"
            }
  
            if ($inactiveUsers -and $inactiveDevices) {
                $combinedResult.FindingSummary += "both inactive users and devices."
            }
            elseif ($inactiveUsers) {
                $combinedResult.FindingSummary += "inactive users."
            }
            else {
                $combinedResult.FindingSummary += "inactive devices."
            }
  
            $results += $combinedResult
        }
        else {
            $result = @{
                Description            = "No inactive users or devices found."
                Severity               = "Informational"
                LikelihoodOfCompromise = "Low"
                Findings          = $null
                FindingSummary          = "No inactive users or devices found."
                Score                  = $null
                Remediation            = "No action required."
                Status                 = "Pass"
            }
            $results += $result
        }
    }
    catch {
        $errstr = $_.exception.message
        $result = @{
            Description            = "Error checking inactive users or devices."
            Severity               = "High"
            LikelihoodOfCompromise = "High"
            Findings          = $null
            FindingSummary          = "Error: $errstr"
            Score                  = $null
            Remediation            = "Investigate and resolve the issue."
            Status                 = "Fail"
        }
  
        Write-Warning $result.FindingSummary
        $results += $result
    }
  
    return $results
  }

$accessToken = $args[0]
Check-InactiveUsersOrDevices -AccessToken $accessToken
