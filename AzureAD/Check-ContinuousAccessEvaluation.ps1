function Check-ContinuousAccessEvaluation {
    param (
        [string]$AccessToken
    )

    $result = @{
        ItemNumber = "AADS014"
        UseCase = "Continuous Access"
        WeightedScore = 9.09
        TechnicalInformation = "Continuous Access Evaluation (CAE) allows real-time re-evaluation of user sessions when critical security events occur, like location changes or password resets. Without CAE, an attacker could exploit access for a longer duration, even after security events, maintaining session control even when it should be revoked."
        Category = "Authentication & Permission Policies"
        TechnicalDetails = $null # will fullfill later 
        RemedediationSolution = 
        "Enable Continuous Access Evaluation (CAE) to enhance security:

1. Access Azure Portal: Sign in as a global administrator.
2. Navigate to Azure AD: Go to Azure Active Directory > Security > Conditional Access.
3. Create New Policy: Click 'New policy'.
4. Name the Policy: Enter 'Continuous Access Evaluation' as the policy name.
5. Set Assignments: Define users, groups, and cloud apps for CAE application.
6. Configure Session Controls: In policy settings, locate 'Session controls'.
7. Enable CAE: Select 'Customize continuous access evaluation' and enable the option.
8. Apply Changes: Save the policy.
9. Verify: Confirm CAE activation in the policy overview for selected users/groups.
10. Monitor: Regularly review CAE effectiveness and adjust as needed.

Note: Implement CAE gradually, starting with a pilot group before full deployment."
        MITREMapping = "[MITRE] T1110: Brute Force"
        Status = $null
        ErrorMsg = $null 
    }

    # $results = @()

    # Define your resource URI (replace with your specific URI)
    $resourceUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    try {
        $conditionalAccessPolicies = Invoke-RestMethod -Uri $resourceUri -Method Get -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        $caContinuousAccessEval = $conditionalAccessPolicies.value | Where-Object { $_.displayName -eq "Continuous Access Evaluation" }

        if ($caContinuousAccessEval) {
            $result.Status = "Pass"
            $result.TechnicalDetails = "Continuous Access Evaluation is enabled."
        } else {
            $result.Status = "Fail"
            $result.TechnicalDetails = "Continuous Access Evaluation is disabled."
        }
    }
    catch {
        $result.Status = "Error"
        $result.ErrorMsg = $_.Exception.Message
        $result.TechnicalDetails = "Error occurred while checking Continuous Access Evaluation status."
    }

    return $result
}

$accessToken = $args[0]
Check-ContinuousAccessEvaluation -AccessToken $accessToken