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
Powershell module to allow multiple way of connectivity toward multiple Microsoft Graph

.DESCRIPTION
This Powershell module can be used to connect to Microsoft Graph API but also other Graph API leveraging Azure AD
Currently, it is possible to used (as long as the Graph API allow it) Credential, Application with Client Secret 
and Application with Certificate for authentication.

.EXAMPLE
Manual API call to get Email Activity
Invoke-GraphApi -TenantName Contoso -Resource reports -QueryParams "getEmailActivityUserDetail(period='D180')" -ClientID $ClientID -ClientSecret $ClientSecret

.NOTES
Other Source for Powershell Graph API Module 
- https://github.com/Ryan2065/MSGraphCmdlets Only Credential but Really flexible Invoke
- https://github.com/markekraus/PSMSGraph Focus on Application, seem quite robust.

List of Major Graph Service : https://docs.microsoft.com/en-us/graph/overview-major-services
#>

#### Generic Function ####
#From : https://stackoverflow.com/questions/4192971/in-powershell-how-do-i-convert-datetime-to-unix-time/
function ConvertFromCtime ([Int]$ctime) {
    [datetime]$epoch = '1970-01-01 00:00:00'    
    [datetime]$result = $epoch.AddSeconds($Ctime)
    return $result
}

#From : https://devblogs.microsoft.com/scripting/powertip-convert-from-utc-to-my-local-time-zone/
function Convert-UTCtoLocal
{
param(
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

Function Validate-TenantName
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
    $TenantName = Validate-TenantName -TenantName $TenantName
    if($LoginSource -eq "EvoSTS")
    {
        $webrequest = Invoke-WebRequest -Uri https://login.windows.net/$($TenantName)/.well-known/openid-configuration  -UseBasicParsing
    }
    else {
        $webrequest = Invoke-WebRequest -Uri https://login.microsoftonline.com/$($TenantName)/.well-known/openid-configuration  -UseBasicParsing
    }
    if($webrequest.StatusCode -eq 200){
        $webrequest.content.replace("{","").replace("}","").split(",") | Foreach{ if($_ -like '*:*'){ $TenantInfo[(($_.split(":")[0]).replace('"',''))]= ($_.substring($($_.split(":")[0]).length +1)).replace('"','') } }
    }
    Return $TenantInfo
}

#### Authentication Function ####
#TODO : AcquireTokenSilentAsync to check from Cache (UPN/CERT)
# https://github.com/AzureAD/azure-activedirectory-library-for-dotnet/wiki/AcquireTokenSilentAsync-using-a-cached-token

## UPN
function Get-OAuthHeaderUPN
{
	[cmdletbinding()]
	param(
    [Parameter(Mandatory = $True)]
      	[string]$TenantName ,
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
    $TenantName = Validate-TenantName -TenantName $TenantName
    IF([string]::IsNullOrEmpty($UserPrincipalName))
    {
        $UserPrincipalName = Get-CurrentUPN
    }
    $TenantInfo = Get-TenantLoginEndPoint -TenantName $TenantName
	#Azure DLL are sideloaded in a job to bypass potential conflict with other version
	$job = Start-Job -ArgumentList $TenantName,$UserPrincipalName,$AzureADDLL,$clientId,$redirectUri,$resourceAppIdURI,$TenantInfo -ScriptBlock {
		$TenantName = $args[0]
		$UserPrincipalName = $args[1]
		$AzureADDLL = $args[2]
		$clientId = $args[3]
        $redirectUri = $args[4]
        $resourceAppIdURI = $args[5]
        $TenantInfo = $args[6]
        
		$tMod = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)
      
        [string] $authority = $($TenantInfo.get_item("authorization_endpoint"))
		$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
		$PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
		$platformParam = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList $PromptBehavior
		$userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList $UserPrincipalName, "OptionalDisplayableId"
		$authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParam, $userId)
		$AuthHeader=$authResult.result.CreateAuthorizationHeader()
		$headers = @{
            "Authorization" = $AuthHeader
            "Content-Type"  = "application/json"
            "ExpiresOn"     = $authResult.Result.ExpiresOn
            "AppID"     = $ClientID
            "UserID"     = $UserPrincipalName
          }
		Return $headers
	}
	$Wait = Wait-Job $job
    $jobResult = Receive-Job $job
    Remove-Job $job
	Return $jobResult
}

## App (client secret)
#ToDo

## App (client secret) W/O DLL
# Based on https://www.altitude365.com/2018/09/23/retrieve-and-analyze-office-365-usage-data-with-powershell-and-microsoft-graph-api/
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
    
    $TenantName = Validate-TenantName -TenantName $TenantName

    #Login Endpoint info
    $loginURL = ($(Get-TenantLoginEndPoint -TenantName $TenantName)).get_item("token_endpoint")

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resourceURI;client_id=$ClientID;client_secret=$ClientSecret}
    $oauth = Invoke-RestMethod -Method Post -Uri "$($loginURL)?api-version=1.0" -Body $body

    #Let's put the oauth token in the header, where it belongs
    $ExpireOn = "$(ConvertFromCtime -ctime $oauth.expires_on)"
    $headers = @{
        "Authorization" = "$($oauth.token_type) $($oauth.access_token)"
        "ExpiresOn"     = $ExpireOn
        "AppID"     = $ClientID
    }
    Return $headers
}

## App (Cert)
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
    $TenantName = Validate-TenantName -TenantName $TenantName
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
    $authResult = $authContext.AcquireTokenASync($resourceURI, $cac)

    # Check if authentication is successfull.
    if ($authResult.IsFaulted -eq $True)
    {
        Write-Error "No Access Token"
    }
    else
    {
    # Perform REST call.
        $AuthHeader=$authResult.result.CreateAuthorizationHeader()
        $headers = @{
            "Authorization" = $AuthHeader
            "Content-Type"  = "application/json"
            "ExpiresOn"     = $authResult.Result.ExpiresOn
            "AppID"     = $ClientID
        }
    Return $headers
    }
}

#### Request Function ####
#Generic Graph API Request
Function Invoke-GraphApi
{
    [CmdletBinding(DefaultParameterSetName='UPN')]
    Param(
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [Parameter(ParameterSetName='UPN', Mandatory=$True)]
        [String]
        $TenantName,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [Parameter(ParameterSetName='UPN', Mandatory=$True)]
        [String]
        $Resource,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [Parameter(ParameterSetName='UPN', Mandatory=$True)]
        [String]
        $QueryParams,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$False)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$False)]
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
        [String]
        [ValidateSet(
            'Default',
            'Delete',
            'Get',
            'Head',
            'Merge',
            'Options',
            'Patch',
            'Post',
            'Put',
            'Trace'
        )]
        $Method = "Get",
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='UPN', Mandatory=$True)]
        [String]
        $ClientID,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [String]
        $ClientSecret,
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [String]
        $CertificatePath,
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [String]
        $CertificatePassword,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$False)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$False)]
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
        [String]
        $APIVersion = "v1.0",
        [Parameter(ParameterSetName='ClientCert', Mandatory=$false)]
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$false)]
        [Parameter(ParameterSetName='UPN', Mandatory=$True)]
      	[string]$redirectUri,
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
        [string]
        $UserPrincipalName
    )
    $resourceURI = "https://graph.microsoft.com"
    switch ( $PsCmdlet.ParameterSetName )
    {
        "UPN"
        {
            if($Global:UPNGraphHeader){
                # Setting DateTime to Universal time to work in all timezones
                $DateTime = (Get-Date).ToUniversalTime()
        
                # If the authToken exists checking when it expires
                $TokenExpires = ($Global:UPNGraphHeader.ExpiresOn.datetime - $DateTime).Minutes
                $UPNMismatch = $UserPrincipalName -ne $Global:UPNGraphHeader.UserID
                $AppIDMismatch = $ClientID -ne $Global:UPNGraphHeader.AppID
                if($TokenExpires -le 0 -or $UPNMismatch -or $AppIDMismatch){
                    write-host "Authentication need to be refresh" -ForegroundColor Yellow
                    $Global:UPNGraphHeader = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceURI -UserPrincipalName $UserPrincipalName
                }
            }
            # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
            else {
                $Global:UPNGraphHeader = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceURI -UserPrincipalName $UserPrincipalName
            }
            $GraphHeader = $Global:UPNGraphHeader
        }
        "ClientSecret"
        {
            if($Global:CSGraphHeader){
                # Setting DateTime to Universal time to work in all timezones
                $DateTime = (Get-Date).ToUniversalTime()
        
                # If the authToken exists checking when it expires
                $TokenExpires = ((Get-date ($Global:CSGraphHeader.ExpiresOn)) - $DateTime).Minutes
                $AppIDMismatch = $ClientID -ne $Global:CSGraphHeader.AppID
                if($TokenExpires -le 0 -or $AppIDMismatch){
                    write-host "Authentication need to be refresh" -ForegroundColor Yellow
                $Global:CSGraphHeader = Get-OAuthHeaderAppClientSecretNoDLL -TenantName $TenantName -clientId $ClientID -ClientSecret $ClientSecret -resourceURI $ResourceURI
                }
            }
            # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
            else {
                $Global:CSGraphHeader = Get-OAuthHeaderAppClientSecretNoDLL -TenantName $TenantName -clientId $ClientID -ClientSecret $ClientSecret -resourceURI $ResourceURI
            }
            $GraphHeader = $Global:CSGraphHeader
        }
        "ClientCert"
        {
            if($Global:CCGraphHeader){
                # Setting DateTime to Universal time to work in all timezones
                $DateTime = (Get-Date).ToUniversalTime()
        
                # If the authToken exists checking when it expires
                $TokenExpires = ($Global:CCGraphHeader.ExpiresOn.datetime - $DateTime).Minutes
                $AppIDMismatch = $ClientID -ne $Global:CCGraphHeader.AppID
                if($TokenExpires -le 0 -or $AppIDMismatch){
                    write-host "Authentication need to be refresh" -ForegroundColor Yellow
                    $Global:CCGraphHeader = Get-OAuthHeaderAppCert -ClientID $ClientID -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword -TenantName $TenantName -resourceURI $ResourceURI
                }
            }
            # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
            else {
                $Global:CCGraphHeader = Get-OAuthHeaderAppCert -ClientID $ClientID -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword -TenantName $TenantName -resourceURI $ResourceURI
            }
            $GraphHeader = $Global:CCGraphHeader 
        }
    }
    
    #Allow larger data set with multiple read.
    #From :https://smsagent.blog/2018/10/22/querying-for-devices-in-azure-ad-and-intune-with-powershell-and-microsoft-graph/    
    try {
        $GraphURL = "https://graph.microsoft.com/$($APIVersion)/$($Resource)/$($QueryParams)"
        $GraphResponse = Invoke-RestMethod -Uri $GraphURL -Headers $GraphHeader -Method $Method
    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
     
        }
    
    # Return the data
    if($GraphResponse.Value -eq $null){
        $Items = $GraphResponse
    }else{
        $Items = $GraphResponse.Value
    }
    $NextLink = $GraphResponse.'@odata.nextLink'
    # Need to loop the requests because only 100 results are returned each time
    While ($NextLink -ne $null)
    {
        $GraphResponse = Invoke-RestMethod -Uri $NextLink -Headers $GraphtHeader -Method Get
        $NextLink = $GraphResponse.'@odata.nextLink'
        $Items += $GraphResponse.Value
    }
    Return $Items
}
