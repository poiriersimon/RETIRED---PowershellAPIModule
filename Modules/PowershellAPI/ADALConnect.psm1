#Requires -Version 5.0
################################################################################# 
#  
# The sample scripts are not supported under any Microsoft standard support  
# program or service. The sample scripts are provided AS IS without warranty  
# of any kind. Microsoft further disclaims all implied warranties including, without  
# limitation, any implied warranties of merchantability or of fitness for a particular  
# purpose. The entire risk arising out of the use or performance of the sample scripts  
# and documentation remains with you. In no event shall Microsoft, its authors, or  
# anyone else involved in the creation, production, or delivery of the scripts be liable  
# for any damages whatsoever (including, without limitation, damages for loss of business  
# profits, business interruption, loss of business information, or other pecuniary loss)  
# arising out of the use of or inability to use the sample scripts or documentation,  
# even if Microsoft has been advised of the possibility of such damages 
# 
################################################################################# 

<#
.SYNOPSIS
Powershell module to allow multiple way of connectivity leveraging Azure Active Directory Authentication Libraries (ADAL)

.DESCRIPTION
This Powershell module can be used to connect to Microsoft Graph API but also other Graph API leveraging ADAL
Currently, it is possible to used (as long as the Graph API allow it) Credential, Application with Client Secret 
and Application with Certificate for authentication.

.EXAMPLE
Build the Authentication Header for an Azure AD Apps with Certificate Authentication.
Get-OAuthHeaderAppCert -ClientID $ClientID -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword -TenantName $TenantName -resourceURI $ResourceURI

.NOTES

#>

#### Generic Function ####

function ConvertFrom-Ctime ([Int]$ctime) {
    [datetime]$epoch = '1970-01-01 00:00:00'    
    [datetime]$result = $epoch.AddSeconds($Ctime)
    return $result
}


function Convert-UTCtoLocal
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=$true)]
        [String] $UTCTime
    )

    $strCurrentTimeZone = (Get-WmiObject win32_timezone).StandardName
    $TZ = [System.TimeZoneInfo]::FindSystemTimeZoneById($strCurrentTimeZone)
    $LocalTime = [System.TimeZoneInfo]::ConvertTimeFromUtc($UTCTime, $TZ)
    Return $LocalTime
}
Function Get-AzureADDLL
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [Switch]
        $InstallPreview
    )
    [array]$AzureADModules = Get-Module -ListAvailable | where{$_.name -eq "AzureAD" -or $_.name -eq "AzureADPreview"}
    Try
    {
        if($AzureADModules.count -eq 0 -and $InstallPreview -eq $True)
        {
            Install-Module AzureADPreview -Confirm:$False -Force
        }
        elseif($AzureADModules.count -eq 0)
        {
            Install-Module AzureAD -Confirm:$False -Force
        }
    }
    Catch
    {
        Write-Error "Can't find Azure AD DLL. Install the module manually 'Install-Module AzureAD'"
    }
    
    $AzureDLL = join-path (($AzureADModules | sort version -Descending | Select -first 1).Path | split-Path) Microsoft.IdentityModel.Clients.ActiveDirectory.dll
    Return $AzureDLL
}

Function Get-CurrentUPN
{
	$UserPrincipalName = ([ADSI] "LDAP://<SID=$(([System.Security.Principal.WindowsIdentity]::GetCurrent()).User)>").userPrincipalName
	Return $UserPrincipalName
}

# Proxy Auth
Function Get-AuthProxy
{
    #Do Proxy Auth with Default Network Credential
    $wc = New-Object System.Net.WebClient
    $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
}

Function Test-TenantName
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [System.String]
        $TenantName
    )
    if($TenantName -notlike "*.onmicrosoft.com"){
        $TenantName = $TenantName + ".onmicrosoft.com"
    }
    Return $TenantName
}

Function Get-TenantLoginEndPoint
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True)]
        [System.String]
        $TenantName,
        [Parameter(Mandatory = $false)]
        [System.String]
        [ValidateSet('MicrosoftOnline','EvoSTS')]
        $LoginSource = "EvoSTS"
    )
    $TenantInfo = @{}
    if($LoginSource -eq "EvoSTS")
    {
        $webrequest = Invoke-WebRequest -Uri https://login.windows.net/$($TenantName)/.well-known/openid-configuration -UseBasicParsing
    }
    else {
        $webrequest = Invoke-WebRequest -Uri https://login.microsoftonline.com/$($TenantName)/.well-known/openid-configuration -UseBasicParsing
    }
    if($webrequest.StatusCode -eq 200){
        $webrequest.content.replace("{","").replace("}","").split(",") | Foreach{ if($_ -like '*:*'){ $TenantInfo[(($_.split(":")[0]).replace('"',''))]= ($_.substring($($_.split(":")[0]).length +1)).replace('"','') } }
    }
    Return $TenantInfo
}

#### Authentication Function ####
# https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/wiki/AcquireTokenSilentAsync-using-a-cached-token

## UPN
function Get-OAuthHeaderUPN
{
	[cmdletbinding()]
	param(
    [Parameter(Mandatory = $True)]
      	[string]$clientId,
    [Parameter(Mandatory = $True)]
      	[string]$redirectUri,
    [Parameter(Mandatory = $True)]
      	[string]$resourceAppIdURI,
    [Parameter(Mandatory = $False)]
      	[string]$UserPrincipalName
    )
    $AzureADDLL = Get-AzureADDLL
    if([string]::IsNullOrEmpty($UserPrincipalName))
    {
        $UserPrincipalName = Get-CurrentUPN
    }
    $TenantName = $UserPrincipalName.split("@")[1]
    $TenantInfo = Get-TenantLoginEndPoint -TenantName $TenantName
    $tMod = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
    
    [string] $authority = $($TenantInfo.get_item("authorization_endpoint"))
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
    $platformParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior
    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserPrincipalName, "OptionalDisplayableId"
    Try{
        $authResult = $authContext.AcquireTokenSilentAsync($resourceAppIdURI, $clientId)
        $AuthHeader=$authResult.result.CreateAuthorizationHeader()
    }
    Catch{
    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParam, $userId)
    $AuthHeader=$authResult.result.CreateAuthorizationHeader()
    }
    
    $headers = @{
        "Authorization" = $AuthHeader
        "Content-Type"  = "application/json"
        "ExpiresOn"     = $authResult.Result.ExpiresOn
        "AppID"     = $ClientID
        "UserID"     = $UserPrincipalName
        }
    Return $headers
}

## App (client secret)
#ToDo

## App (client secret) W/O DLL

function Get-OAuthHeaderAppClientSecretNoDLL
{
	[cmdletbinding()]
	param(
    [Parameter(Mandatory = $True)]
      	[string]$TenantName ,
    [Parameter(Mandatory = $True)]
        [string]$clientId,
    [Parameter(Mandatory = $True)]
      	[string]$ClientSecret,
    [Parameter(Mandatory = $True)]
      	[string]$resourceURI
    
    )
    
    $TenantName = Test-TenantName -TenantName $TenantName

    #Login Endpoint info
    $loginURL = ($(Get-TenantLoginEndPoint -TenantName $TenantName)).get_item("token_endpoint")

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resourceURI;client_id=$ClientID;client_secret=$ClientSecret}
    $oauth = Invoke-RestMethod -Method Post -Uri "$($loginURL)?api-version=1.0" -Body $body

    #Let's put the oauth token in the header, where it belongs
    $ExpireOn = "$(ConvertFrom-Ctime -ctime $oauth.expires_on)"
    $headers = @{
        "Authorization" = "$($oauth.token_type) $($oauth.access_token)"
        "ExpiresOn"     = $ExpireOn
        "AppID"     = $ClientID
    }
    Return $headers
}


Function Get-OAuthHeaderAppCert
{
    param (
    [cmdletbinding()]
    [parameter(Mandatory=$true)]
        $ClientID,
    [parameter(Mandatory=$true)]
        $CertificatePath,
    [parameter(Mandatory=$true)]
        $CertificatePassword,
    [parameter(Mandatory=$true)]
        $TenantName,
    [Parameter(Mandatory = $True)]
      	[string]$resourceURI
    )
    $TenantName = Test-TenantName -TenantName $TenantName
    $AzureADDLL = Get-AzureADDLL

    #Load Certificate
    $flag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    $AppCert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword, $flag )
    
    #Login Endpoint info
    $authority = ($(Get-TenantLoginEndPoint -TenantName $TenantName)).get_item("authorization_endpoint")
    
    #Can't sideload the DLL for this one since the AppCert isn't pass correclty.
    $tMod = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
    # Create Authentication Context tied to Azure AD Tenant
    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
    $cac = New-Object  Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate($clientID, $AppCert)
    Try{
        $authResult = $authContext.AcquireTokenSilentAsync($resourceAppIdURI, $clientId)
        $AuthHeader=$authResult.result.CreateAuthorizationHeader()
    }
    Catch{
        $authResult = $authContext.AcquireTokenASync($resourceURI, $cac)
        if ($authResult.IsFaulted -eq $True)
        {
            Write-Error "No Access Token"
        }
        else
        {
            $AuthHeader=$authResult.result.CreateAuthorizationHeader()
        }
    }
     
    # Perform REST call.
        $headers = @{
            "Authorization" = $AuthHeader
            "Content-Type"  = "application/json"
            "ExpiresOn"     = $authResult.Result.ExpiresOn
            "AppID"     = $ClientID
        }
    Return $headers
    
}

#Read Cached Token 
Function Get-TokenCache
{
    $AzureADDLL = Get-AzureADDLL
    $tMod = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
    $cache = [Microsoft.IdentityModel.Clients.ActiveDirectory.TokenCache]::DefaultShared
    if($cache.count -gt 0){
        Return $cache.ReadItems() 
    }
}