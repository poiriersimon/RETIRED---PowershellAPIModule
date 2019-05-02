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
Short description

.DESCRIPTION
Long description

.PARAMETER InstallPreview
Parameter description

.EXAMPLE
An example

.NOTES
General notes
#>

#### Generic Function ####
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
	$UserPrincipalName = $NULL
	#
	$UPNList = @()
	$UPN = $Env:USERNAME
	if($UPN -eq $NULL){
		$UPN = (whoami)
		if($UPN -ne $NULL){
			$UPN = $UPN.split("\")[-1]
		}else{
			$Proc = Get-CimInstance Win32_Process -Filter "name = 'powershell.exe'"
			if($proc.GetType().BaseType.name -eq "Array"){
				foreach($process in $proc){
					$UPNList += Invoke-CimMethod -InputObject $process -MethodName GetOwner | select -ExpandProperty User
				}
				$UPN = $UPNList | select -first 1
			}else{
				$UPN = Invoke-CimMethod -InputObject $process -MethodName GetOwner | select -ExpandProperty User
			}
		}
	}
	
	#Find UPN
	$strFilter = "(&(objectCategory=User)(SAMAccountName=$($UPN)))"
	$objDomain = New-Object System.DirectoryServices.DirectoryEntry
	$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
	$objSearcher.SearchRoot = $objDomain
	$objSearcher.PageSize = 1
	$objSearcher.Filter = $strFilter
	$objSearcher.SearchScope = "Subtree"
	$objSearcher.PropertiesToLoad.Add("userprincipalname") | Out-Null
	$colResults = $objSearcher.FindAll()
	[string]$UserPrincipalName = $colResults[0].Properties.userprincipalname
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
        [Parameter(Mandatory = $false)]
        [System.String]
        $TenantName,
        [Parameter(Mandatory = $false)]
        [System.String]
        [ValidateSet('Azure','O365')]
        $LoginSource
    )
    $TenantInfo = @{}
    $TenantName = Validate-TenantName -TenantName $TenantName
    if($LoginSource -eq "Azure")
    {
        $webrequest = Invoke-WebRequest -Uri https://login.windows.net/$($TenantName)/.well-known/openid-configuration
    }
    else {
        $webrequest = Invoke-WebRequest -Uri https://login.microsoftonline.com/$($TenantName)/.well-known/openid-configuration
    }
    if($webrequest.StatusCode -eq 200){
        $webrequest.content.replace("{","").replace("}","").split(",") | Foreach{ if($_ -like '*:*'){ $TenantInfo[(($_.split(":")[0]).replace('"',''))]= ($_.substring($($_.split(":")[0]).length +1)).replace('"','') } }
    }
    Return $TenantInfo
}

#### Authentication Function ####

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
    [Parameter(Mandatory = $True)]
    [ValidateSet('Azure','O365')]
      	[string]$LoginSource,
    [Parameter(Mandatory = $False)]
      	[string]$UserPrincipalName
    )
    $AzureADDLL = Get-AzureADDLL
    $TenantName = Validate-TenantName -TenantName $TenantName
    IF([string]::IsNullOrEmpty($UserPrincipalName))
    {
        $UserPrincipalName = Get-CurrentUPN
    }
    $TenantInfo = Get-TenantLoginEndPoint -TenantName $TenantName -LoginSource $LoginSource
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

        #[string] $authority = "https://login.microsoftonline.com/$TenantName"
        
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
          }
		Return $headers
	}
	$Wait = Wait-Job $job
	$jobResult = Receive-Job $job
	Return $jobResult
}

## App (client secret)

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
    [ValidateSet('Azure','O365')]
      	[string]$LoginSource,
    [Parameter(Mandatory = $True)]
      	[string]$resourceURI
    
    )
    
    $TenantName = Validate-TenantName -TenantName $TenantName

    #Login Endpoint info
    $loginURL = ($(Get-TenantLoginEndPoint -TenantName $TenantName -LoginSource $LoginSource)).get_item("token_endpoint")

    # Get an Oauth 2 access token based on client id, secret and tenant domain
    $body = @{grant_type="client_credentials";resource=$resourceURI;client_id=$ClientID;client_secret=$ClientSecret}
    $oauth = Invoke-RestMethod -Method Post -Uri "$($loginURL)?api-version=1.0" -Body $body

    #Let's put the oauth token in the header, where it belongs
    $headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

    Return $headerParams
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
    [ValidateSet('Azure','O365')]
        [string]$LoginSource,
    [Parameter(Mandatory = $True)]
      	[string]$resourceURI
    )
    $TenantName = Validate-TenantName -TenantName $TenantName
    $AzureADDLL = Get-AzureADDLL

    #Load Certificate
    $flag = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    $AppCert  = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath, $CertificatePassword, $flag )
    
    #Login Endpoint info
    $authority = ($(Get-TenantLoginEndPoint -TenantName $TenantName -LoginSource $LoginSource)).get_item("authorization_endpoint")

   #Azure DLL are sideloaded in a job to bypass potential conflict with other version
	$job = Start-Job -ArgumentList $AzureADDLL,$authority,$clientId,$AppCert,$resourceURI -ScriptBlock {
		$AzureADDLL = $args[0]
		$authority = $args[1]
		$clientId = $args[2]
        $AppCert = $args[3]
        $resourceURI = $args[4]
        
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
            }
		Return $headers
	    }
	$Wait = Wait-Job $job
	$jobResult = Receive-Job $job
	Return $jobResult
    }    
}


#### Connectivity Function ####
## PreDefine Commun Graph Endpoint
### Manage Office

### Intune
Function Connect-Intune{
    param
(
    [Parameter(Mandatory = $True)]
    [string]$TenantName,
    [Parameter(Mandatory = $False)]
    [string]$UserPrincipalName
)
    #Connect to Intune Graph API
    # Checking if authToken exists before running authentication
    [string]$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    [string]$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    [string]$resourceUri = "https://graph.microsoft.com"

    if($Global:IntuneAuthToken){
        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($Global:IntuneAuthToken.ExpiresOn.datetime - $DateTime).Minutes

            if($TokenExpires -le 0){

            write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            $Global:IntuneAuthToken = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $clientid -redirectUri $redirectUri -resourceAppIdURI $resourceUri -LoginSource O365 -UserPrincipalName $UserPrincipalName
            }
    }
    # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
    else {
        $Global:IntuneAuthToken = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $clientid -redirectUri $redirectUri -resourceAppIdURI $resourceUri -LoginSource O365 -UserPrincipalName $UserPrincipalName
    }
    $Global:IntuneAuthToken
}

### Security
### Microsoft Graph
# Call EWS
## User + Impersonnation

## EXO without Click2Run
#Ref : https://www.michev.info/Blog/Post/1771/hacking-your-way-around-modern-authentication-and-the-powershell-modules-for-office-365
#Only Support User Connection no Application Connect (As Of : 2019-05)
Function Connect-EXOPSSession
{
    param (
    [cmdletbinding()]
    [parameter(Mandatory=$true)]
        $TenantName,
    [parameter(Mandatory=$False)]
        $UserPrincipalName
    )
    $AzureADDLL = Get-AzureADDLL
    $TenantName = Validate-TenantName -TenantName $TenantName
    IF([string]::IsNullOrEmpty($UserPrincipalName))
    {
        $UserPrincipalName = Get-CurrentUPN
    }
    
    $resourceUri = "https://outlook.office365.com"
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $clientid = "a0c73c16-a7e3-4564-9a95-2bdf47383716"

    $Result = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $clientid -redirectUri $redirectUri -resourceAppIdURI $resourceUri -LoginSource O365 -UserPrincipalName $UserPrincipalName

    $Authorization =  $Result.Authorization
    $Password = ConvertTo-SecureString -AsPlainText $Authorization -Force
    $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $UserPrincipalName, $Password
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/PowerShell-LiveId?BasicAuthToOAuthConversion=true -Credential $Ctoken -Authentication Basic -AllowRedirection
    Import-PSSession $Session
}

#### Call Function ####