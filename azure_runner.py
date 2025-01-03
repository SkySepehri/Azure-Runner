import requests
import json
from datetime import datetime, timedelta
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import uuid

def get_ms_graph_access_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default"
    }

    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        if access_token:
            print("Successfully Authenticated to Microsoft Graph")
            return access_token
        else:
            print("Error: No access token returned.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error getting MSGraph Access Token: {e}")
        return None

def run_azure_scripts_concurrently(agentId, orgId, domainControllerId, domainControllerClientId, domainControllerTenetId, domainControllerClientSecret, domainControllerName):
    access_token = get_ms_graph_access_token(domainControllerTenetId, domainControllerClientId, domainControllerClientSecret)
    if not access_token:
        return {"Status": "Error", "ErrorMsg": "Failed to retrieve access token"}

    runId = str(uuid.uuid4())

    tasks = {
        "Password Reset Check": (check_aadc_connect_sync_account_password_reset, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Unverified Publishers Check": (check_allow_unverified_app_publishers, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "All Users MFA Check": (check_all_users_mfa, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Azure AD Role Changes Check": (check_azure_ad_role_changes, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Continuous Access Evaluation Check": (check_continuous_access_evaluation, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Custom Banned Password Protection Check": (check_custom_banned_password_protection_enabled, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Dangerous API Permissions Check": (check_dangerous_api_permissions, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "DSC Enabled Check": (check_dsc_enabled_using_graph_api, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Elevate Subscription Access Check": (check_elevate_subscription_access, [domainControllerTenetId, domainControllerClientId, domainControllerClientSecret, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Global Administrators Check": (check_global_administrators, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Inactive Users or Devices Check": (check_inactive_users_or_devices, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Legacy Authentication Check": (check_legacy_authentication, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Non-Admin App Registration Permission Check": (check_non_admin_app_registration_permission, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Password Hash Sync Vulnerability Check": (check_password_hash_sync_vulnerability, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Private IP in Named Locations Check": (check_private_ip_in_named_locations, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Privileged Roles for Guest Accounts Check": (check_privileged_roles_for_guest_accounts, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Security Defaults Check": (check_security_defaults, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Tenant Creation Policies Check": (check_tenant_creation_policies, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Unrestricted Guest Enumeration Check": (check_unrestricted_guest_enumeration, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "AAD Connect Takeover Detection Check": (detect_aad_connect_takeover, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Azure VM Contributor Role Assignments Check": (get_azuread_virtual_machine_contributor_role_assignments, [access_token, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Managed Identities Check": (get_managed_identities, [domainControllerTenetId, domainControllerClientId, domainControllerClientSecret, agentId, orgId, runId, domainControllerId, domainControllerName]),
        "Azure Run As Account Test": (test_azure_run_as_account, [domainControllerTenetId, domainControllerClientId, domainControllerClientSecret, agentId, orgId, runId, domainControllerId, domainControllerName]),
    }

    with ThreadPoolExecutor() as executor:
        futures = {
            executor.submit(func, *args, task_name=task_name): task_name
            for task_name, (func, args) in tasks.items()
        }

        results = {}
        for future in futures:
            task_name = futures[future]
            try:
                results[task_name] = future.result()
            except Exception as e:
                results[task_name] = {"Status": "Error", "ErrorMsg": str(e)}

        return results

## Azure Scripts
def check_aadc_connect_sync_account_password_reset(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS002",
        "UseCase": "AAD Connect - Password reset",
        "WeightedScore": 25,
        "TechnicalInformation": (
            "When you install Entra ID Connect to sync identities between your on-premises environment and Entra ID, a user named MSOL_[0-9a-f]{12} is created in both directories. "
            "This user has broad permissions and is often excluded from security defaults and conditional access policies. "
            "If an attacker gains admin access to the Entra ID Connect server, they can extract this user's password and use it to reset passwords or gain access to AAD, particularly if syncing admin accounts with global admin permissions.\n\n"
            "In the on-premises environment, the MSOL_ user typically has the ability to reset passwords and read them using DCSync. "
            "This access can allow an attacker to obtain the krbtgt password and create golden or silver Kerberos tickets."
        ),
        "Category": "Account Hygiene",
        "TechnicalDetails": None,  # will fulfill later
        "RemedediationSolution": (
            "Treat your Entra ID (Azure AD) Connect server with the same security rigor as a domain controller. "
            "Avoid syncing admin accounts between AD and AAD, establish a trust boundary between the directories, "
            "and limit the MSOL_ user's capabilities to only necessary organizational units and users. "
            "Additionally, follow Microsoft’s hardening recommendations for added security."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        aad_connect_uri = "https://graph.microsoft.com/v1.0/servicePrincipals"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = requests.get(aad_connect_uri, headers=headers)
        response.raise_for_status()
        service_principals = response.json().get("value", [])

        aad_connect_sync_account = next(
            (sp for sp in service_principals if sp.get("displayName") == "Windows Azure Active Directory Connector"),
            None
        )

        if not aad_connect_sync_account:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = "Fail: Azure AD Connect sync account not found."
        else:
            password_reset_enabled = next(
                (role for role in aad_connect_sync_account.get("appRoles", []) if role.get("value") == "Reset Password"),
                None
            )
            if password_reset_enabled:
                result["Status"] = "Pass"
                result["TechnicalDetails"] = "Pass: Password reset is enabled for Azure AD Connect sync account."
            else:
                result["Status"] = "Fail"
                result["TechnicalDetails"] = "Fail: Password reset is not enabled for Azure AD Connect sync account."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Fail"
        result["TechnicalDetails"] = f"Error: {str(e)}"

    return result

def check_allow_unverified_app_publishers(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS016",
        "UseCase": "Applications from Unverified Publishers in Azure",
        "WeightedScore": 9.09,
        "TechnicalInformation": (
            "Applications from unverified publishers, whose identities aren't validated by Microsoft, may introduce untrusted or malicious software into your environment. "
            "Attackers can use these apps to gain unauthorized access, bypass security measures, or extract sensitive data from your Azure environment."
        ),
        "Category": "Authentication & Permission Policies",
        "TechnicalDetails": None,
        "RemedediationSolution": (
            "1. Sign in to the Azure portal as a Global Administrator.\n"
            "2. Navigate to Azure Active Directory > Enterprise applications > Consent and permissions.\n"
            "3. Under 'Admin consent settings', configure the following:\n"
            "   - Set 'Users can request admin consent to apps they are unable to consent to' to 'No'.\n"
            "   - Ensure 'Selected users can request admin consent to apps they are unable to consent to' is not enabled.\n"
            "4. Click 'Save' to apply the changes."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        user_settings_uri = "https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        response = requests.get(user_settings_uri, headers=headers)
        response.raise_for_status()
        user_settings = response.json()

        allow_unverified_app_publishers = user_settings.get("isEnabled", False)

        if not allow_unverified_app_publishers:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "Users are not allowed to add apps from unverified publishers."
        else:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = "Users are allowed to add apps from unverified publishers. This poses a security risk."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Error checking AllowUnverifiedAppPublishers setting: {str(e)}"

    return result

def check_all_users_mfa(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS022",
        "UseCase": "Ensure Multi-Factor Authentication (MFA) is enabled for all users",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Multi-Factor Authentication adds an extra layer of security to user accounts "
            "by requiring additional verification beyond just a password."
        ),
        "Category": "Identity and Access Management",
        "TechnicalDetails": None,
        "RemedediationSolution": (
            "Enable MFA for all users without it. This can be done through the Azure Active Directory portal "
            "or by using PowerShell scripts."
        ),
        "MITREMapping": "T1078 - Valid Accounts",
        "Status": None,
        "ErrorMsg": None,
    }
    try:
        users_without_mfa = []
        next_link = "https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,userType&$filter=userType eq 'Member'&$top=999"
        total_users = 0

        while next_link:
            response = requests.get(
                next_link,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            response.raise_for_status()
            data = response.json()
            total_users += len(data.get("value", []))

            for user in data.get("value", []):
                user_id = user["id"]
                mfa_response = requests.get(
                    f"https://graph.microsoft.com/v1.0/users/{user_id}/authentication/methods",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                mfa_response.raise_for_status()
                mfa_methods = mfa_response.json().get("value", [])
                if not any(
                    method["@odata.type"] in [
                        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                        "#microsoft.graph.phoneAuthenticationMethod",
                        "#microsoft.graph.fido2AuthenticationMethod",
                        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
                        "#microsoft.graph.emailAuthenticationMethod",
                    ]
                    for method in mfa_methods
                ):
                    users_without_mfa.append(user["userPrincipalName"])

            next_link = data.get("@odata.nextLink")

        users_with_mfa = total_users - len(users_without_mfa)
        result["TechnicalDetails"] = (
            f"Total users: {total_users}. Users with MFA: {users_with_mfa}. "
            f"Users without MFA: {len(users_without_mfa)}."
        )
        if users_without_mfa:
            result["TechnicalDetails"] += f" Users without MFA: {', '.join(users_without_mfa)}"
        result["Status"] = "Pass" if not users_without_mfa else "Fail"
    except Exception as e:
        result["Status"] = "Fail"
        result["ErrorMsg"] = f"Error checking MFA status: {str(e)}"

    return result

def check_azure_ad_role_changes(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    # Define an array of roles to check for
    roles_to_check = ["Global Administrator", "Company Administrator", "Privileged Authentication Administrator", "Privileged Role Administrator"]
    
    result = {
        "ItemNumber": "AADS005",
        "UseCase": "Azure AD Roles",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Assigning inappropriate Entra ID (Azure AD) roles to a user or application can create a pathway to global admin access. "
            "Specifically, the Privileged Authentication Administrator role essentially grants Global Admin-level permissions, as it allows "
            "resetting the password of any Global Admin, modifying MFA settings, and potentially taking over their account.\n\n"
            "The Privileged Role Administrator role allows its holder to assign additional Entra ID (Azure AD) roles to any user, including "
            "the Global Administrator role. This role also extends to API permissions, enabling the user to grant consent for any permission "
            "to any application."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Carefully manage and audit role assignments in Azure AD. Limit high-privilege roles to trusted personnel and regularly review role "
            "assignments and API permissions to prevent unauthorized access. Implement strong role-based access controls and monitor for any "
            "suspicious changes."
        ),
        "MITREMapping": "[MITRE] T1098: Account Manipulation",
        "Status": None,
        "ErrorMsg": None
    }

    # Get Azure AD audit logs
    uri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
    audit_logs = []

    while uri:
        try:
            response = requests.get(uri, headers={"Authorization": f"Bearer {access_token}"})
            response.raise_for_status()
            data = response.json()
            audit_logs.extend(data['value'])
            uri = data.get('@odata.nextLink', None)
        except requests.exceptions.RequestException as e:
            result["ErrorMsg"] = f"Failed to retrieve audit logs: {e}"
            result["Status"] = "Error"
            return result

    # Filter audit logs for potential role changes based on activity display name
    potential_role_changes = [
        log for log in audit_logs if (
            "Add member to role" in log.get('activityDisplayName', '') or
            "Remove member from role" in log.get('activityDisplayName', '') or
            "Add eligible member to role" in log.get('activityDisplayName', '') or
            "Remove eligible member from role" in log.get('activityDisplayName', '') or
            "Update role" in log.get('activityDisplayName', '')
        ) and log.get('category') == "RoleManagement"
    ]
    
    role_changes = []

    for role_change in potential_role_changes:
        target_resources = role_change.get('targetResources', [])
        modified_properties = role_change.get('modifiedProperties', [])

        if target_resources and len(target_resources) > 0:
            role_name = next(
                (prop['newValue'] for prop in modified_properties if prop['displayName'] == "Role.DisplayName"), None
            )
            if role_name:
                role_name = role_name.strip('"')
                if role_name in roles_to_check:
                    role_changes.append({
                        "Activity": role_change.get('activityDisplayName'),
                        "Role": role_name,
                        "Initiator": role_change.get('initiatedBy', {}).get('user', {}).get('userPrincipalName'),
                        "DateTime": role_change.get('activityDateTime')
                    })

    # Set TechnicalDetails and Status
    if role_changes:
        result["TechnicalDetails"] = "Role changes detected for specified roles:\n" + "\n".join(
            [f"Activity: {change['Activity']}, Role: {change['Role']}, Initiator: {change['Initiator']}, DateTime: {change['DateTime']}" for change in role_changes]
        )
        result["Status"] = "Fail"
    else:
        result["TechnicalDetails"] = "No role changes detected for specified roles (Global Administrator, Company Administrator, Privileged Authentication Administrator, Privileged Role Administrator)."
        result["Status"] = "Pass"

    print(result["TechnicalDetails"])
    return result

def check_continuous_access_evaluation(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS014",
        "UseCase": "Continuous Access",
        "WeightedScore": 9.09,
        "TechnicalInformation": (
            "Continuous Access Evaluation (CAE) allows real-time re-evaluation of user sessions when critical security events occur, "
            "like location changes or password resets. Without CAE, an attacker could exploit access for a longer duration, even after "
            "security events, maintaining session control even when it should be revoked."
        ),
        "Category": "Authentication & Permission Policies",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Enable Continuous Access Evaluation (CAE) to enhance security:\n\n"
            "1. Access Azure Portal: Sign in as a global administrator.\n"
            "2. Navigate to Azure AD: Go to Azure Active Directory > Security > Conditional Access.\n"
            "3. Create New Policy: Click 'New policy'.\n"
            "4. Name the Policy: Enter 'Continuous Access Evaluation' as the policy name.\n"
            "5. Set Assignments: Define users, groups, and cloud apps for CAE application.\n"
            "6. Configure Session Controls: In policy settings, locate 'Session controls'.\n"
            "7. Enable CAE: Select 'Customize continuous access evaluation' and enable the option.\n"
            "8. Apply Changes: Save the policy.\n"
            "9. Verify: Confirm CAE activation in the policy overview for selected users/groups.\n"
            "10. Monitor: Regularly review CAE effectiveness and adjust as needed.\n\n"
            "Note: Implement CAE gradually, starting with a pilot group before full deployment."
        ),
        "MITREMapping": "[MITRE] T1110: Brute Force",
        "Status": None,
        "ErrorMsg": None
    }

    resource_uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    try:
        response = requests.get(resource_uri, headers={"Authorization": f"Bearer {access_token}"})
        response.raise_for_status()
        conditional_access_policies = response.json()

        ca_continuous_access_eval = next(
            (policy for policy in conditional_access_policies.get('value', []) if policy.get('displayName') == "Continuous Access Evaluation"),
            None
        )

        if ca_continuous_access_eval:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "Continuous Access Evaluation is enabled."
        else:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = "Continuous Access Evaluation is disabled."
    
    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = str(e)
        result["TechnicalDetails"] = "Error occurred while checking Continuous Access Evaluation status."
    
    return result

def check_custom_banned_password_protection_enabled(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS001",
        "UseCase": "Banned Passwords Protection",
        "WeightedScore": 25,
        "TechnicalInformation": (
            "A banned password policy prevents users from setting weak or commonly used passwords by blacklisting specific terms. "
            "Without this protection, attackers can exploit weak passwords through dictionary attacks or credential stuffing, increasing "
            "the risk of unauthorized access. Enabling custom banned password protection strengthens security by preventing the use of easily guessable passwords."
        ),
        "Category": "Account Hygiene",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Consider enabling custom banned password protection for enhanced security.\n"
            "Login: Sign in to the Azure Active Directory portal as a global administrator.\n"
            "Navigate: Go to Azure Active Directory > Security > Authentication methods.\n"
            "Select: Click on Password protection.\n"
            "Toggle: Set Enforce custom list to Yes.\n"
            "Enter: Add your custom banned passwords in the Custom banned password list.\n"
            "Save: Click Save to apply the changes."
        ),
        "MITREMapping": "[MITRE] T1110: Brute Force",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        # Define the resource URI for querying authentication policies
        auth_policies_uri = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"

        # Retrieve authentication policies
        response = requests.get(auth_policies_uri, headers={"Authorization": f"Bearer {access_token}"})
        response.raise_for_status()  # Raise an exception if the request failed
        auth_policies = response.json()

        # Check if custom banned password protection is enabled
        banned_password_policy = next(
            (policy for policy in auth_policies.get('passwordPolicies', []) if policy.get('name') == "BannedPasswords"),
            None
        )

        if banned_password_policy and banned_password_policy.get('enabled'):
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "Custom banned password protection is enabled. BannedPasswordProtectionEnabled: True"
        else:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = "Custom banned password protection is not enabled. BannedPasswordProtectionEnabled: False"

        return result

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = str(e)
        result["TechnicalDetails"] = "Error occurred while checking custom banned password protection."
        return result

def check_dangerous_api_permissions(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS004",
        "UseCase": "Dangerous API Permissions",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Enterprise Applications and application registrations are crucial components of Entra ID (Azure AD). Managing applications in Entra ID involves granting "
            "appropriate permissions to these apps. When an application is granted app permissions, it can access Microsoft Graph endpoints and related data irrespective of "
            "user login status. The app can authenticate using secrets or certificates to access this data.\n\n"
            "Certain permissions are extensive and potentially risky. If an attacker gains sufficient permissions, they can create a custom app registration, assign additional "
            "permissions to it, and use this app as a backdoor to the tenant."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Watch out for the following permissions and remove them if possible:\n\n"
            "Application.ReadWrite.All - Grants the application the permission to act as other entities.\n"
            "AppRoleAssignment.ReadWrite.All - Grants the application the permission to grant additional privileges to itself.\n"
            "RoleManagement.ReadWrite.Directory - Grants the application the permission to grant additional privileges to itself, other applications, or any user."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    dangerous_api_permissions = {
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory -> directly promote yourself to GA",
        "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All -> grant yourself RoleManagement.ReadWrite.Directory, then promote to GA",
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All -> act as another entity e.g. GA"
    }

    findings = []

    try:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        applications_uri = "https://graph.microsoft.com/v1.0/applications"
        applications_response = requests.get(applications_uri, headers=headers)
        applications_response.raise_for_status()
        tenant_applications = applications_response.json().get("value", [])

        for tenant_application in tenant_applications:
            service_principals_uri = f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{tenant_application['appId']}'"
            service_principals_response = requests.get(service_principals_uri, headers=headers)
            service_principals_response.raise_for_status()
            service_principals = service_principals_response.json().get("value", [])

            for service_principal in service_principals:
                role_assignments_uri = f"https://graph.microsoft.com/v1.0/servicePrincipals/{service_principal['id']}/appRoleAssignments"
                role_assignments_response = requests.get(role_assignments_uri, headers=headers)
                role_assignments_response.raise_for_status()
                role_assignments = role_assignments_response.json().get("value", [])

                for role_assignment in role_assignments:
                    if role_assignment["appRoleId"] in dangerous_api_permissions:
                        findings.append({
                            "objectId": tenant_application["id"],
                            "DisplayName": tenant_application["displayName"],
                            "GrantedPermission": dangerous_api_permissions[role_assignment["appRoleId"]],
                            "Type": "AppRegistration"
                        })
                        findings.append({
                            "objectId": service_principal["id"],
                            "DisplayName": service_principal["displayName"],
                            "GrantedPermission": dangerous_api_permissions[role_assignment["appRoleId"]],
                            "Type": "ServicePrincipal"
                        })

        if not findings:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "No dangerous API permissions detected."
        else:
            result["Status"] = "Fail"
            technical_details = "Potentially dangerous API permissions detected:\n\n"
            for finding in findings:
                technical_details += f"Object ID: {finding['objectId']}\n"
                technical_details += f"Display Name: {finding['DisplayName']}\n"
                technical_details += f"Granted Permission: {finding['GrantedPermission']}\n"
                technical_details += f"Type: {finding['Type']}\n\n"
            result["TechnicalDetails"] = technical_details

        return result

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = str(e)
        result["TechnicalDetails"] = "Error occurred during API call. Investigate the error and retry."
        return result
    
def check_dsc_enabled_using_graph_api(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS009",
        "UseCase": "Check if Desired State Configuration is Enabled",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Desired State Configuration (DSC) is a built-in Windows Server feature that uses a central service and the Local Configuration Manager (LCM) to apply configurations automatically. "
            "With Azure Automation State Configuration, admins can deploy changes across servers, but attackers could exploit this to deploy malicious configurations or backdoors."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,
        "RemedediationSolution": (
            "Limit access to Azure Automation and DSC services, enforce least privilege for those managing configurations, regularly audit applied configurations, and monitor for unauthorized changes or suspicious deployments."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        # Define the endpoint to get the list of all service principals
        graph_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        headers = {
            "Authorization": f"Bearer {access_token}"
        }

        # Invoke the Graph API to get the list of all service principals
        response = requests.get(graph_url, headers=headers)
        response.raise_for_status()
        service_principals = response.json().get("value", [])

        # Filter service principals with appDisplayName equal to 'Microsoft Automation'
        dsc_enabled_principals = [
            principal for principal in service_principals
            if principal.get("appDisplayName") == "Microsoft Automation"
        ]

        if dsc_enabled_principals:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = (
                f"DSC is enabled for {len(dsc_enabled_principals)} service principal(s):\n"
                f"{dsc_enabled_principals}"
            )
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "Pass: No service principals with DSC enabled found."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = str(e)

    return result

def check_elevate_subscription_access(tenant_id, client_id, client_secret, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS011",
        "UseCase": "Elevate Azure Subscription Access",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "An Azure subscription is a logical container in Microsoft Azure used to manage resources like virtual machines, databases, and storage. "
            "It groups resources for billing, access control, and organization. Each subscription is associated with one or more Azure Active Directory (Entra ID) tenants and can have role-based access controls (Azure RBAC) to manage permissions. "
            "Elevate Azure Subscription Access allows attackers with elevated roles to gain significant permissions in Azure."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,
        "RemedediationSolution": (
            "Limit assignments of elevated roles, use Privileged Identity Management (PIM) for just-in-time access, enforce MFA, regularly audit role assignments, disable Access management for Azure resources if unnecessary, and apply least privilege and Conditional Access policies."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        # Get an access token
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        token_data = {
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
            "client_id": client_id,
            "client_secret": client_secret
        }
        token_response = requests.post(token_url, data=token_data)
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")

        # Define the list of elevated roles
        elevated_roles = {
            "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
            "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Access Administrator",
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
            "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
            "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator"
        }

        # Fetch role assignments
        graph_url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        headers = {"Authorization": f"Bearer {access_token}"}
        role_assignments_response = requests.get(graph_url, headers=headers)
        role_assignments_response.raise_for_status()
        role_assignments = role_assignments_response.json().get("value", [])

        # Filter for elevated roles
        elevation_users = [
            assignment for assignment in role_assignments
            if assignment.get("roleDefinitionId") in elevated_roles
        ]

        # Fetch user details
        elevation_users_details = []
        for user in elevation_users:
            user_url = f"https://graph.microsoft.com/v1.0/users/{user.get('principalId')}"
            user_response = requests.get(user_url, headers=headers)
            user_response.raise_for_status()
            user_details = user_response.json()
            elevation_users_details.append({
                "DisplayName": user_details.get("displayName"),
                "UserPrincipalName": user_details.get("userPrincipalName"),
                "RoleName": elevated_roles.get(user.get("roleDefinitionId"))
            })

        if elevation_users_details:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = {
                "ElevationUsers": elevation_users_details
            }
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "No elevated subscription access found."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = str(e)

    return result

def check_global_administrators(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS006",
        "UseCase": "Azure AD Global Administrators",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Having too many Global Administrators increases the attack surface, as attackers can target these accounts "
            "to gain full control of the tenant. If compromised, a Global Admin account can give attackers unrestricted "
            "access to Azure resources, allowing them to escalate privileges, modify security settings, and cause significant harm."
        ),
        "Category": "Lateral Movement Analysis",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Limit the number of Global Administrators to only what is necessary. Regularly review and audit admin accounts, "
            "enforce MFA, and use Privileged Identity Management (PIM) for just-in-time access."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    resource_uri = "https://graph.microsoft.com/v1.0/directoryRoles"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }

    try:
        directory_roles = requests.get(resource_uri, headers=headers).json()
        global_admin_role = next(
            (role for role in directory_roles.get("value", []) if role.get("displayName") == "Global Administrator"),
            None
        )

        if not global_admin_role:
            result["Status"] = "Fail"
            result["ErrorMsg"] = "Global Administrator role not found."
            return result

        members_uri = f"{resource_uri}/{global_admin_role['id']}/members"
        global_admin_members = requests.get(members_uri, headers=headers).json()

        global_admin_details = [
            f"Display Name: {member.get('displayName')}, UPN: {member.get('userPrincipalName')}"
            for member in global_admin_members.get("value", [])
        ]
        num_global_admins = len(global_admin_details)

        result["TechnicalDetails"] = (
            f"Number of Global Administrators: {num_global_admins}\n\nGlobal Administrators:\n" +
            "\n".join(global_admin_details)
        )
        result["Status"] = "Pass" if num_global_admins <= 5 else "Fail"

    except Exception as e:
        result["Status"] = "Fail"
        result["ErrorMsg"] = str(e)

    return result

def check_inactive_users_or_devices(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    results = []

    user_resource_uri = "https://graph.microsoft.com/v1.0/users"
    device_resource_uri = "https://graph.microsoft.com/v1.0/devices"
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        # Fetch users
        inactive_users_response = requests.get(user_resource_uri, headers=headers).json()
        inactive_users = [
            {
                "DisplayName": user.get("displayName"),
                "UserPrincipalName": user.get("userPrincipalName"),
                "LastSignIn": user.get("signInSessionsValidFromDateTime")
            }
            for user in inactive_users_response.get("value", [])
            if not user.get("signInSessionsValidFromDateTime") or
               datetime.fromisoformat(user["signInSessionsValidFromDateTime"][:-1]) < datetime.utcnow() - timedelta(days=30)
        ]

        # Fetch devices
        inactive_devices_response = requests.get(device_resource_uri, headers=headers).json()
        inactive_devices = [
            {
                "DeviceName": device.get("displayName"),
                "LastSignIn": device.get("approximateLastSignInDateTime")
            }
            for device in inactive_devices_response.get("value", [])
            if not device.get("approximateLastSignInDateTime") or
               datetime.fromisoformat(device["approximateLastSignInDateTime"][:-1]) < datetime.utcnow() - timedelta(days=30)
        ]

        if inactive_users:
            results.append({
                "ItemNumber": "AADS003",
                "UseCase": "Identify Inactive Users or Devices in Active Directory",
                "WeightedScore": 3,
                "TechnicalInformation": (
                    "This use case identifies inactive user accounts or devices in Active Directory. Inactive accounts "
                    "or devices can pose a security risk as they may be exploited by attackers to gain unauthorized access "
                    "to the network. Regularly identifying and managing inactive accounts helps reduce the attack surface "
                    "and improve overall security."
                ),
                "Category": "Account Hygiene",
                "TechnicalDetails": inactive_users,
                "RemediationSolution": (
                    "Regularly review and disable or remove inactive user accounts and devices to minimize security risks. "
                    "Ensure that only active and necessary accounts and devices are maintained in Active Directory."
                ),
                "MITREMapping": "[MITRE] T1078: Valid Accounts",
                "Status": "Fail",
                "ErrorMsg": None
            })

        if inactive_devices:
            results.append({
                "ItemNumber": "AADS003",
                "UseCase": "Identify Inactive Users or Devices in Active Directory",
                "WeightedScore": 3,
                "TechnicalInformation": (
                    "This use case identifies inactive user accounts or devices in Active Directory. Inactive accounts "
                    "or devices can pose a security risk as they may be exploited by attackers to gain unauthorized access "
                    "to the network. Regularly identifying and managing inactive accounts helps reduce the attack surface "
                    "and improve overall security."
                ),
                "Category": "Account Hygiene",
                "TechnicalDetails": inactive_devices,
                "RemediationSolution": (
                    "Regularly review and disable or remove inactive user accounts and devices to minimize security risks. "
                    "Ensure that only active and necessary accounts and devices are maintained in Active Directory."
                ),
                "MITREMapping": "[MITRE] T1078: Valid Accounts",
                "Status": "Fail",
                "ErrorMsg": None
            })

        if not results:
            results.append({
                "ItemNumber": "AADS003",
                "UseCase": "Identify Inactive Users or Devices in Active Directory",
                "WeightedScore": 3,
                "TechnicalInformation": (
                    "This use case identifies inactive user accounts or devices in Active Directory. Inactive accounts "
                    "or devices can pose a security risk as they may be exploited by attackers to gain unauthorized access "
                    "to the network. Regularly identifying and managing inactive accounts helps reduce the attack surface "
                    "and improve overall security."
                ),
                "Category": "Account Hygiene",
                "TechnicalDetails": None,
                "RemediationSolution": (
                    "Regularly review and disable or remove inactive user accounts and devices to minimize security risks. "
                    "Ensure that only active and necessary accounts and devices are maintained in Active Directory."
                ),
                "MITREMapping": "[MITRE] T1078: Valid Accounts",
                "Status": "Pass",
                "ErrorMsg": None
            })

    except Exception as e:
        results.append({
            "ItemNumber": "AADS003",
            "UseCase": "Error checking inactive users or devices.",
            "WeightedScore": 3,
            "TechnicalInformation": "An error occurred while checking for inactive users or devices in Azure AD.",
            "Category": "Account and Device Management",
            "TechnicalDetails": None,
            "RemediationSolution": "Investigate and resolve the issue.",
            "MITREMapping": "[MITRE] T1078: Valid Accounts",
            "Status": "Fail",
            "ErrorMsg": str(e)
        })

    return results

def check_legacy_authentication(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS018",
        "UseCase": "Exploiting Legacy Authentication",
        "WeightedScore": 9.09,
        "TechnicalInformation": (
            "Legacy authentication refers to older authentication protocols and methods, such as Basic Authentication, "
            "which are less secure compared to modern alternatives like OAuth 2.0."
        ),
        "Category": "Authentication & Permission Policies",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "To address potential legacy authentication vulnerabilities, follow these steps:\n\n"
            "1. Sign in to the Azure Portal (https://portal.azure.com) as a Global Administrator.\n"
            "2. Navigate to Azure Active Directory > Security > Authentication methods.\n"
            "3. Review the list of enabled authentication methods.\n"
            "4. For each potentially vulnerable method (email and SMS):\n"
            "   a. Click on the method to open its settings.\n"
            "   b. Set the 'Enable' toggle to 'No' to disable the method.\n"
            "   c. Click 'Save' to apply the changes.\n"
            "5. Enable more secure authentication methods if not already active:\n"
            "   a. Enable and configure Microsoft Authenticator app.\n"
            "   b. Set up FIDO2 security keys.\n"
            "   c. Configure Windows Hello for Business.\n"
            "6. After disabling less secure methods, monitor sign-in logs for any failed authentication attempts using legacy protocols.\n"
            "7. Implement Conditional Access policies to further restrict legacy authentication attempts.\n\n"
            "Remember to communicate these changes to your users and provide support for transitioning to more secure authentication methods."
        ),
        "MITREMapping": "[MITRE] T1110: Brute Force",
        "Status": None,
        "ErrorMsg": None
    }

    settings_uri = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
    headers = {"Authorization": f"Bearer {access_token}"}

    try:
        response = requests.get(settings_uri, headers=headers)
        response.raise_for_status()
        auth_settings = response.json()

        legacy_auth_possible = False
        enabled_methods = []

        for method in auth_settings.get("authenticationMethodConfigurations", []):
            if method.get("state") == "enabled":
                method_id = method.get("id")
                enabled_methods.append(method_id)
                if method_id in ["email", "sms"]:
                    legacy_auth_possible = True

        if legacy_auth_possible:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = (
                f"Potential legacy authentication methods are enabled: {', '.join(enabled_methods)}. "
                "Email and SMS methods can be used with legacy protocols."
            )
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = (
                f"No legacy authentication methods detected. Enabled methods: {', '.join(enabled_methods)}"
            )

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Failed to check authentication settings: {str(e)}"

    return result

def check_non_admin_app_registration_permission(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS015",
        "UseCase": "Allowing Non-Admin Users to Register Custom Applications",
        "WeightedScore": 9.09,
        "TechnicalInformation": (
            "Allowing non-admin users to register custom applications opens the possibility for attackers to create malicious "
            "app registrations that request high-level permissions. This could lead to unauthorized access, privilege escalation, "
            "and broader attacks across the Azure AD environment."
        ),
        "Category": "Authentication & Permission Policies",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Limit app registration permissions to administrators and audit the registration of applications in your Azure AD "
            "environment to mitigate potential abuse."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        # Check authorization policy
        policy_uri = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        headers = {"Authorization": f"Bearer {access_token}"}
        policy_response = requests.get(policy_uri, headers=headers)
        policy_response.raise_for_status()
        policy = policy_response.json()

        default_user_role_permissions = policy.get("value", [{}])[0].get("defaultUserRolePermissions", {})
        allowed_to_create_apps = default_user_role_permissions.get("allowedToCreateApps", False)

        if allowed_to_create_apps:
            result["Status"] = "Fail"

            # Fetch all users
            users_uri = "https://graph.microsoft.com/v1.0/users?$select=userPrincipalName,userType"
            users_response = requests.get(users_uri, headers=headers)
            users_response.raise_for_status()
            users = users_response.json()

            non_admin_users = [
                user["userPrincipalName"]
                for user in users.get("value", [])
                if user.get("userType") == "Member"
            ]
            result["TechnicalDetails"] = (
                "Non-admin users are allowed to register custom applications. "
                f"The following users have this ability: {', '.join(non_admin_users)}"
            )
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = (
                "Non-admin users are not allowed to register custom applications. "
                "This setting is disabled in the default user role permissions."
            )

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Error checking non-admin app registration permission: {str(e)}"

    return result

def check_password_hash_sync_vulnerability(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS020",
        "UseCase": "Password Hash Sync Vulnerability",
        "WeightedScore": 9.09,
        "TechnicalInformation": (
            "Password Hash Synchronization (PHS) involves synchronizing password hashes between on-premises and cloud directories, "
            "such as Azure AD. Vulnerabilities in PHS can expose password hashes to unauthorized access, potentially leading to credential theft "
            "or compromise. Checking for PHS vulnerabilities involves ensuring that synchronization processes are secure, password hashes are properly "
            "protected, and appropriate access controls are in place to mitigate the risk of exploitation."
        ),
        "Category": "Authentication & Permission Policies",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Ensure Azure AD Connect is not using insecure configurations, and review SYNC_ account permissions and MSOL_ users. "
            "Take necessary actions to secure these configurations."
        ),
        "MITREMapping": "[MITRE] T1552: Unsecured Credentials",
        "Status": None,
        "ErrorMsg": None,
        "Findings": []
    }

    try:
        findings = []

        # Step 1: Check if Azure AD Connect is installed
        try:
            subprocess.run(["sc", "query", "ADSync"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            findings.append("Azure AD Connect is installed.")
        except subprocess.CalledProcessError:
            findings.append("Azure AD Connect is not installed.")

        # Step 2: Check for MSOL_ users in Active Directory (requires pywinrm or equivalent AD module)
        try:
            msol_users = subprocess.run(
                ["powershell", "-Command", "Get-ADUser -Filter \"SamAccountName -like 'MSOL_*'\" -Properties * | Select-Object -ExpandProperty SamAccountName"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            ).stdout.strip().splitlines()

            if msol_users:
                findings.append("Found users with MSOL_ attribute identity:")
                findings.extend(msol_users)
            else:
                findings.append("No users with MSOL_ attribute identity found.")
        except Exception as e:
            findings.append(f"Error checking MSOL_ users: {str(e)}")

        # Step 3: Check for SYNC_ accounts in Azure AD with password reset permissions
        try:
            aad_connect_uri = "https://graph.microsoft.com/v1.0/servicePrincipals"
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(aad_connect_uri, headers=headers)
            response.raise_for_status()
            service_principals = response.json().get("value", [])

            sync_accounts = [sp for sp in service_principals if "Sync_" in sp.get("displayName", "")]
            if sync_accounts:
                for account in sync_accounts:
                    app_roles = account.get("appRoles", [])
                    reset_permissions = any(role.get("value") == "Reset Password" for role in app_roles)
                    if reset_permissions:
                        findings.append(f"SYNC_ account '{account['displayName']}' has password reset permissions in Azure AD.")
                    else:
                        findings.append(f"SYNC_ account '{account['displayName']}' does not have password reset permissions in Azure AD.")
            else:
                findings.append("No SYNC_ accounts found in Azure AD.")
        except requests.exceptions.RequestException as e:
            findings.append(f"Error checking SYNC_ accounts: {str(e)}")

        # Determine the status
        if "Azure AD Connect is installed." in findings and any("MSOL_" in f for f in findings) and any("SYNC_" in f for f in findings):
            result["Status"] = "Fail"
            result["TechnicalDetails"] = "Vulnerability detected: All conditions for a Password Hash Synchronization vulnerability are present."
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "No vulnerability detected: Not all conditions for a Password Hash Synchronization vulnerability are present."

        result["Findings"] = findings

    except Exception as e:
        result["TechnicalDetails"] = f"Error: {str(e)}"
        result["Status"] = "Error"

    return result

def check_private_ip_in_named_locations(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS019",
        "UseCase": "Check for Private IP Addresses in Named Locations",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "This function checks for the presence of private IP addresses in named locations within Azure Active Directory Conditional Access policies. "
            "Private IP addresses should not be used in named locations as they can lead to misconfigurations and potential security risks. "
            "Attackers can exploit these misconfigurations to bypass security controls and gain unauthorized access."
        ),
        "Category": "Authentication & Permission Policies",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Review and remove any private IP addresses from named locations in Conditional Access policies. "
            "Ensure that only public IP addresses are used to define named locations to maintain proper security boundaries."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    private_ip_pattern = re.compile(r"^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)")

    try:
        # Fetch named locations
        named_locations_url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations"
        headers = {"Authorization": f"Bearer {access_token}"}
        named_locations_response = requests.get(named_locations_url, headers=headers)
        named_locations_response.raise_for_status()
        named_locations = named_locations_response.json().get("value", [])

        # Extract IP ranges from named locations
        named_location_ips = []
        for location in named_locations:
            ip_ranges = location.get("ipRanges", [])
            named_location_ips.extend(ip_ranges)

        # Check for private IP addresses
        private_ips = [ip_range for ip_range in named_location_ips if private_ip_pattern.match(ip_range.get("cidrAddress", ""))]

        if private_ips:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = f"Private IP addresses found in named locations: {private_ips}"
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "No private IP addresses found in named locations."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = str(e)

    return result

def check_privileged_roles_for_guest_accounts(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS012",
        "UseCase": "Privileged Roles for Guest Account",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Privileged roles in Active Directory provide elevated access and control over resources. "
            "Assigning such roles to guest accounts can pose a significant security risk, as these external or temporary accounts "
            "may not adhere to the same security standards as internal users. Attackers exploiting these roles could gain unauthorized access "
            "to sensitive systems and data, potentially compromising the entire environment."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "To address the issue of privileged roles assigned to guest accounts:\n\n"
            "1. Review all guest accounts with privileged roles identified in the audit.\n"
            "2. For each guest account:\n"
            "   a. Evaluate the business need for the privileged role assignment.\n"
            "   b. If the privileged access is not required, remove the guest account from the role:\n"
            "      - Go to Azure AD Admin Center > Roles and administrators\n"
            "      - Select the specific role\n"
            "      - Find the guest account and remove it from the role\n"
            "   c. If privileged access is necessary, consider the following alternatives:\n"
            "      - Create a separate internal account for the user with appropriate controls\n"
            "      - Implement Privileged Identity Management (PIM) for just-in-time, time-bound access\n"
            "      - Enable multi-factor authentication and conditional access policies for the account\n"
            "3. Implement a regular review process for privileged role assignments, especially for guest accounts.\n"
            "4. Establish and enforce a policy regarding privileged access for external users.\n"
            "5. Set up alerts for any new privileged role assignments to guest accounts.\n"
            "Remember to document all changes and decisions made during this remediation process."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    # Resource URI for directory roles
    resource_uri = "https://graph.microsoft.com/v1.0/directoryRoles"

    try:
        # Get directory roles
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(resource_uri, headers=headers)
        response.raise_for_status()
        directory_roles = response.json().get("value", [])

        guest_accounts_with_privileged_roles = []

        # Check each role for guest members
        for role in directory_roles:
            members_uri = f"https://graph.microsoft.com/v1.0/directoryRoles/{role['id']}/members?$select=userPrincipalName,userType"
            members_response = requests.get(members_uri, headers=headers)
            members_response.raise_for_status()
            members = members_response.json().get("value", [])

            # Filter for guest accounts
            guest_members = [member for member in members if member.get("userType") == "Guest"]
            if guest_members:
                for guest in guest_members:
                    guest_accounts_with_privileged_roles.append({
                        "RoleName": role["displayName"],
                        "GuestUserPrincipalName": guest["userPrincipalName"]
                    })

        # Set technical details and status based on findings
        if guest_accounts_with_privileged_roles:
            result["TechnicalDetails"] = "Guest accounts with privileged roles:\n" + "\n".join(
                [f"{item['RoleName']}: {item['GuestUserPrincipalName']}" for item in guest_accounts_with_privileged_roles]
            )
            result["Status"] = "Fail"
        else:
            result["TechnicalDetails"] = "No guest accounts found with privileged roles assigned."
            result["Status"] = "Pass"

    except requests.exceptions.RequestException as e:
        result["ErrorMsg"] = f"Error checking privileged roles for guest accounts: {str(e)}"
        result["Status"] = "Error"

    return result

def check_security_defaults(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS008",
        "UseCase": "Security Defaults Enabled or Conditional Access Policies Configured",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Security defaults or conditional access policies are crucial for protecting against common identity-related attacks. "
            "They enforce MFA, block legacy authentication, and implement other security measures."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Ensure that either security defaults are enabled or appropriate conditional access policies are configured to protect your Azure AD environment."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    security_defaults_uri = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
    conditional_access_uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

    try:
        # Check Security Defaults
        headers = {"Authorization": f"Bearer {access_token}"}
        security_defaults_response = requests.get(security_defaults_uri, headers=headers)
        security_defaults_response.raise_for_status()
        security_defaults_info = security_defaults_response.json()

        security_defaults_enabled = security_defaults_info.get("isEnabled", False)

        # Check Conditional Access Policies
        conditional_access_response = requests.get(conditional_access_uri, headers=headers)
        conditional_access_response.raise_for_status()
        conditional_access_policies = conditional_access_response.json().get("value", [])

        # Check if any policies are enabled
        has_enabled_policies = any(policy["state"] == "enabled" for policy in conditional_access_policies)

        if security_defaults_enabled:
            result["TechnicalDetails"] = "Security defaults are enabled."
            result["Status"] = "Pass"
        elif has_enabled_policies:
            result["TechnicalDetails"] = "Security defaults are disabled, but conditional access policies are configured."
            result["Status"] = "Pass"
        else:
            result["TechnicalDetails"] = "Security defaults are disabled and no conditional access policies are configured."
            result["Status"] = "Fail"

    except requests.exceptions.RequestException as e:
        result["Status"] = "Fail"
        result["ErrorMsg"] = f"Error checking security settings: {str(e)}"

    return result

def check_tenant_creation_policies(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS007",
        "UseCase": "Misconfigured Tenant Creation Policies",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Misconfigured tenant creation policies can lead to unauthorized creation of tenants, which attackers can use as an entry point "
            "to create malicious environments, deploy applications, or escalate privileges across environments."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Review and enforce strict policies governing tenant creation. Ensure that only trusted administrators have the right to create "
            "new tenants, and audit tenant creation events regularly."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    graph_uri = "https://graph.microsoft.com/v1.0/organization"

    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        organization_response = requests.get(graph_uri, headers=headers)
        organization_response.raise_for_status()

        organization_data = organization_response.json()
        policies = organization_data["value"][0].get("resourceAccessPolicies", [])

        non_admin_tenant_creation_allowed = any(
            policy["resourceType"] == "Microsoft.AzureActiveDirectory/Tenant" and policy["principalType"] == "User"
            for policy in policies
        )

        if non_admin_tenant_creation_allowed:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = "Non-admin users are allowed to create Azure AD tenants. This poses a security risk as it could lead to unauthorized tenant creation."
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "Only administrators are allowed to create Azure AD tenants, which is the recommended secure configuration."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Error checking tenant creation policies: {str(e)}"
        result["TechnicalDetails"] = f"An error occurred while checking tenant creation policies: {result['ErrorMsg']}"

    return result

def check_unrestricted_guest_enumeration(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS021",
        "UseCase": "Exploiting Unrestricted Guest Access in Azure AD",
        "WeightedScore": 20,
        "TechnicalInformation": (
            "Unrestricted guest access can be exploited by attackers to perform reconnaissance, enumerating users and groups within the tenant. "
            "This information can facilitate further attacks like privilege escalation or lateral movement, compromising the security of the Azure AD environment."
        ),
        "Category": "Lateral Movement Analyst",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "1. Review guest user access:\n"
            "   - Audit all guest users in your Azure AD tenant.\n"
            "   - Identify and document the purpose of each guest account.\n\n"
            "2. Implement least privilege principle:\n"
            "   - Remove unnecessary group memberships and permissions from guest accounts.\n"
            "   - Ensure guest users have access only to resources they absolutely need.\n\n"
            "3. Configure Azure AD external collaboration settings:\n"
            "   - Go to Azure AD > External Identities > External collaboration settings.\n"
            "   - Set Guest user access restrictions to Limited access or a more restrictive option.\n\n"
            "4. Enable Conditional Access policies for guest users:\n"
            "   - Create policies that require multi-factor authentication for guest access.\n"
            "   - Implement device compliance checks for guest users if applicable.\n\n"
            "5. Regularly monitor and review guest user activities:\n"
            "   - Set up Azure AD audit logs to track guest user actions.\n"
            "   - Implement automated alerts for suspicious guest user activities.\n"
        ),
        "MITREMapping": "[MITRE] T1087: Account Discovery",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        guest_users_uri = "https://graph.microsoft.com/v1.0/users?$filter=userType eq 'Guest'"
        headers = {"Authorization": f"Bearer {access_token}"}
        guest_users_response = requests.get(guest_users_uri, headers=headers)
        guest_users_response.raise_for_status()

        guest_users = guest_users_response.json()
        unrestricted_guests = []

        for guest_user in guest_users.get("value", []):
            permissions_uri = f"https://graph.microsoft.com/v1.0/users/{guest_user['id']}/memberOf"
            permissions_response = requests.get(permissions_uri, headers=headers)
            permissions_response.raise_for_status()

            guest_permissions = permissions_response.json()

            if len(guest_permissions.get("value", [])) > 0:
                unrestricted_guests.append(guest_user)

        if unrestricted_guests:
            result["Status"] = "Fail"
            guest_user_names = ', '.join([guest["userPrincipalName"] for guest in unrestricted_guests])
            result["TechnicalDetails"] = f"Found {len(unrestricted_guests)} guest users with potentially dangerous permissions. Guest users: {guest_user_names}"
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "No guest users with potentially dangerous permissions found."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Error checking unrestricted guest enumeration: {str(e)}"

    return result

def detect_aad_connect_takeover(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS017",
        "UseCase": "AAD Connect - Application takeover",
        "WeightedScore": 9.09,
        "TechnicalInformation": (
            "An attacker can use the Microsoft Graph permissions granted to the AAD Connect account, specifically the Entra ID role 'Directory Synchronization Accounts', "
            "to take ownership of any enterprise application in Microsoft Entra ID (Azure AD) and add new credentials. These credentials may not be visible in the portal UI "
            "and only via Graph requests. The attacker can then sign in using this application and gain its permissions, potentially equivalent to Global Admin."
        ),
        "Category": "Authentication & Permission Policies",
        "TechnicalDetails": None,
        "RemediationSolution": (
            "Regularly audit and restrict permissions of Directory Synchronization Accounts. Monitor for unusual credential additions to enterprise applications, "
            "especially those not visible in the portal UI. Implement least privilege access and use conditional access policies to secure critical accounts and applications."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        # Get all enterprise applications
        url = "https://graph.microsoft.com/v1.0/applications"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()
        applications = response.json().get("value", [])

        suspicious_apps = []

        for app in applications:
            # Check for credentials not visible in UI or with auto-generated names
            credential_url = f"https://graph.microsoft.com/v1.0/applications/{app['id']}/passwordCredentials"
            credential_response = requests.get(credential_url, headers=headers)
            credential_response.raise_for_status()

            suspicious_credentials = [
                cred for cred in credential_response.json().get("value", [])
                if not cred.get("displayName") or "Password uploaded on" in cred.get("displayName", "")
            ]

            if len(suspicious_credentials) > 0:
                suspicious_apps.append({
                    "AppId": app.get("appId"),
                    "DisplayName": app.get("displayName"),
                    "SuspiciousCredentials": len(suspicious_credentials)
                })

        if len(suspicious_apps) == 0:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "No suspicious credentials detected for enterprise applications."
        else:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = (
                f"Suspicious credentials detected for enterprise applications. This could indicate a potential takeover attempt. "
                f"Findings: {json.dumps(suspicious_apps)}"
            )

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Error checking for suspicious credentials: {str(e)}"

    return result

def get_azuread_virtual_machine_contributor_role_assignments(access_token, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS013",
        "UseCase": "Identify Azure AD Virtual Machine Contributor Role Assignments",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "This function retrieves and identifies all users and service principals assigned the Virtual Machine Contributor role "
            "in Azure Active Directory. The Virtual Machine Contributor role grants significant permissions, including the ability "
            "to manage virtual machines. If misconfigured, attackers can exploit these permissions to gain control over virtual machines, "
            "potentially leading to unauthorized access and data breaches."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": "The function checks for Virtual Machine Contributor role assignments and searches for Run Command events "
                             "in the subscription activity log over the last 30 days.",
        "RemediationSolution": (
            "Regularly review and audit role assignments to ensure that only authorized users and service principals have the "
            "Virtual Machine Contributor role. Remove any unnecessary or unauthorized assignments to minimize security risks."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }
    
    start_date = datetime.now() - timedelta(days=30)
    end_date = datetime.now()

    try:
        # Get role assignments
        role_url = "https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments"
        headers = {"Authorization": f"Bearer {access_token}"}
        role_response = requests.get(role_url, headers=headers)
        role_response.raise_for_status()
        role_assignments = role_response.json().get("value", [])

        # Check for Virtual Machine Contributor role assignments
        vm_contributor_role_assignments = [
            role for role in role_assignments
            if role["roleDefinitionName"] == "Virtual Machine Contributor"
        ]

        if vm_contributor_role_assignments:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = "Virtual Machine Contributor role assignments found: " + json.dumps(vm_contributor_role_assignments, separators=(",", ":"))
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "No Virtual Machine Contributor role assignments found."

        # Get log events related to Run Command on Virtual Machine
        log_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/microsoft.insights/eventtypes/management/values"
        params = {
            "api-version": "2017-04-01",
            "$filter": f"eventTimestamp ge {start_date.isoformat()} and eventTimestamp le {end_date.isoformat()} and resourceType eq 'Microsoft.Compute/virtualMachines/extensions'",
        }
        log_response = requests.get(log_url, headers=headers, params=params)
        log_response.raise_for_status()
        log_events = log_response.json().get("value", [])

        # Check if any log events are related to Run Command on Virtual Machine
        run_command_events = [
            event for event in log_events
            if event.get("operationName") == "Microsoft.Compute/virtualMachines/extensions/runCommand/action"
        ]

        if run_command_events:
            result["Status"] = "Fail"
            result["TechnicalDetails"] += "\nRun Command events detected for Virtual Machine Contributor role assignments: " + json.dumps(run_command_events, separators=(",", ":"))

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Error checking for VM Contributor role assignments and run command events: {str(e)}"

    return result

def get_managed_identities(tenant_id, client_id, client_secret, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS010",
        "UseCase": "Retrieve Managed Identities",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "Managed Identities allow resources like virtual machines to access other resources without handling credentials. "
            "However, if a managed identity is granted excessive permissions, an attacker could exploit it to control resources. "
            "For example, a virtual machine with a managed identity that has contributor access to a subscription can potentially "
            "take over all resources within that subscription and move laterally to other virtual machines."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,  # Will be populated later
        "RemediationSolution": (
            "Follow the principle of least privilege by assigning minimal permissions to managed identities, regularly audit "
            "access, and monitor for suspicious activity. Avoid granting overly broad roles like contributor at the subscription level."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        # Get an access token
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        body = {
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
            "client_id": client_id,
            "client_secret": client_secret
        }
        token_response = requests.post(token_url, data=body)
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]

        # Get managed identities using Microsoft Graph API
        graph_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        headers = {"Authorization": f"Bearer {access_token}"}
        managed_identities_response = requests.get(graph_url, headers=headers)
        managed_identities_response.raise_for_status()
        managed_identities = [
            identity for identity in managed_identities_response.json().get("value", [])
            if "WindowsAzureActiveDirectoryManagedIdentity" in identity.get("tags", [])
        ]

        if managed_identities:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = f"Managed identities found: {json.dumps(managed_identities, separators=(',', ':'))}"
        else:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "No managed identities found."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Error retrieving managed identities: {str(e)}"

    return result

def test_azure_run_as_account(tenant_id, client_id, client_secret, agentId, orgId, runId, domainControllerId, domainControllerName, task_name):
    result = {
        "ItemNumber": "AADS023",
        "UseCase": "Test Azure Run As Account",
        "WeightedScore": 5,
        "TechnicalInformation": (
            "This function tests the Azure Run As Account to ensure it is properly configured and has the necessary permissions. "
            "Misconfigured Run As Accounts can lead to unauthorized access and potential security risks."
        ),
        "Category": "Object Privilege & Configuration",
        "TechnicalDetails": None,  # Will be populated later
        "RemediationSolution": (
            "Ensure that the Azure Run As Account is properly configured with the necessary permissions and regularly review "
            "and audit its access."
        ),
        "MITREMapping": "[MITRE] T1078: Valid Accounts",
        "Status": None,
        "ErrorMsg": None
    }

    try:
        # Get an access token
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        body = {
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
            "client_id": client_id,
            "client_secret": client_secret
        }
        token_response = requests.post(token_url, data=body)
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]

        # Get service principals using Microsoft Graph API
        graph_url = "https://graph.microsoft.com/v1.0/servicePrincipals"
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(graph_url, headers=headers)
        response.raise_for_status()

        service_principals = response.json().get("value", [])

        # Look for the AzureRunAsAccount
        run_as_account = next(
            (sp for sp in service_principals if sp["displayName"] == "AzureRunAsAccount"), None
        )

        if run_as_account:
            result["Status"] = "Pass"
            result["TechnicalDetails"] = "Pass: Azure Run As Account is properly configured."
        else:
            result["Status"] = "Fail"
            result["TechnicalDetails"] = "Fail: Azure Run As Account is not found or not properly configured."

    except requests.exceptions.RequestException as e:
        result["Status"] = "Error"
        result["ErrorMsg"] = f"Error testing Azure Run As Account: {str(e)}"

    return result

if __name__ == "__main__":
    TenantID = ""
    ClientID = ""
    ClientSecret = ""
    
    results = run_azure_scripts_concurrently("ag", "or","d_id", ClientID, TenantID, ClientSecret, "DC")
    with open("log.json", "w") as log_file:
        json.dump(results, log_file, indent=4)

    print("Results have been written to log.json")
