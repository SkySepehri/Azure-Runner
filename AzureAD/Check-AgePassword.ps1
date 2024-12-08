
function Check-ObsoleteOS {
    [CmdletBinding()]
    param()
    
    $result = @{
        Description            = "Checks for obsolete operating systems in the Active Directory."
        Severity               = "High"
        LikelihoodOfCompromise = "High"
        Findings          = $null
        FindingSummary          = $null
        Score                  = $null
        Remediation            = "Upgrade or replace obsolete operating systems for enhanced security."
        Status                 = $null
    }
    
    try {
        # Define a list of obsolete operating systems
        $obsoleteOSList = @("Windows XP", "Windows Vista", "Windows 7", "Windows 8", "Windows Server 2003", "Windows Server 2008", "Windows Server 2008 R2")
    
        # Get all computers in the domain
        $computers = Get-ADComputer -Server $settings.'domainController.name' -Filter *
    
        # Check each computer for obsolete operating systems
        $obsoleteOSComputers = foreach ($computer in $computers) {
            $os = $computer.OperatingSystem
    
            if ($obsoleteOSList -contains $os) {
                $computer
            }
        }
    
        if ($obsoleteOSComputers.Count -gt 0) {
            $result.Status = "Fail"
            $result.Findings = $obsoleteOSComputers
            $result.FindingSummary = "Fail: Obsolete operating systems found in the Active Directory."
        } else {
            $result.Status = "Pass"
            $result.FindingSummary = "Pass: No obsolete operating systems found in the Active Directory."
        }
    
    } catch {
        $errstr = $_.Exception.Message
        $result.Status = "Fail"
        $result.FindingSummary = "Error: $errstr"
    }
    
    return $result
    }


Check-ObsoleteOS
