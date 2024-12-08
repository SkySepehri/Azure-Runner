function Get-MSGraphAccessToken {
    ##########################################################################################
    #.SYNOPSIS
    # Gets a Microsoft Graph API Accecss Token.  Returns the Access Token.
    #
    #.DESCRIPTION
    # Gets a Microsoft Graph API Access Token equivalent  with the Azure AD app 
    # 'PowerShell-MSGraph'.  Permissions are granted via Azure AD.  This command uses 
    # the 'client_credential' authorization to Microsoft Graph.  See: 
    # https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow.
    #
    # NOTE: MSGraph's Access Token's only last for ONE hour
    #
    #.PARAMETER TenantID
    # Tenant ID associated with the environment.  This is an O365 Tenant ID.
    #
    #.PARAMETER ClientID
    # The App ID associated with the API call.  Command expects this is the 'Username' of 
    # the 'MSGraph' stored credential of the user.
    #
    #.PARAMETER ClientSecret
    # App secret used to generate the Access Token.  Command expects this is the 'password' of
    # the 'MSGraph' stored credential of the user.
    #
    #.EXAMPLE
    # $AccessToken = Get-MSGraphAccessToken
    #
    #.EXAMPLE
    # $AccessToken = Get-MSGraphAccessToken -TenantID $TenantID -ClientID $ClientID -ClientSecret $ClientSecret
    # 
    #.EXAMPLE
    # $AccessToken = Get-MSGraphAccessToken -TenantID 1234-9876 -ClientID 12345987765 -ClientSecret qwerpouc;lkjqwerpoiuc9870jicice
    # 
    ##########################################################################################
      param (
        # Tenant ID
        [Parameter(Mandatory=$false)]
        [String]
        $TenantID,
    
        # Client ID
        [Parameter(Mandatory=$false)]
        [String]
        $ClientID,
    
        # ClientSecret
        [Parameter(Mandatory=$false)]
        [String]
        $ClientSecret
      )
    
    # BEGIN
    
      # Set the defaults if $ClientID and $ClientSecret aren't found...
      if (!$ClientID -and !$ClientSecret) {
        # Grab the 'MSGraph' Credential from the local session
        $MSGraphCredentials = Get-MessagingCredential -Nickname MSGraph -NonDomainCredentials -NoSave
        if (!$MSGraphCredentials) {
          $tmpstr = "[MSGraph] credential isn't stored in the current PowerShell session.  Run 'Save-Credential' to fix."
          Write-Host $tmpstr -ForegroundColor yellow
          break
        }
    
        if (!$TenantID) {
          $TenantID = Import-Object -Tablename common_objects -Name GraphTenantID
        }
        $ClientID = "ClientIDHere"
        $ClientSecret = "SecretHere"
      }
    
    # PROCESS
      # Build MSGraph Call Body
      $body = @{
        # using client_credentials API authentication method.  Required for automation
        grant_type = "client_credentials"
        client_id = $ClientID
        client_secret = $ClientSecret
        scope = "https://graph.microsoft.com/.default"
      }
    
      try {
        $Authorization = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token" `
    -Method Post `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $body `
    -ErrorAction Stop

    
        $AccessToken = $Authorization.access_token
    
        $tmpstr = "Successfully Authenticated to Microsoft Graph"
        Write-Host $tmpstr -ForegroundColor Green
      }
      catch {
        $errstr = $_.exception.message
        $tmpstr = "Error getting MSGraph Access Token : $errstr"
        write-warning $tmpstr
        return $false
      }
    Write-Host $AccessToken
    # END
      return $AccessToken
    }
  
$TenantID = $args[0]
$ClientID = $args[1]
$ClientSecret = $args[2]

$accessToken = Get-MSGraphAccessToken -TenantID $TenantID -ClientID $ClientID -ClientSecret $ClientSecret