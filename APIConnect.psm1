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
#To Do

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
    $headers = @{
        "Authorization" = "$($oauth.token_type) $($oauth.access_token)"
        "ExpiresOn"     = $authResult.Result.ExpiresOn
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

#### Connectivity Function ####
### Intune
#Only Support User Connection no Application Connect (As Of : 2019-05)
Function Connect-Intune{
    param
(
    [Parameter(Mandatory = $True)]
    [string]$TenantName,
    [Parameter(Mandatory = $False)]
    [string]$UserPrincipalName
)
    #Connect to Intune Graph API
    #For a complete Intune module : #https://github.com/Microsoft/Intune-PowerShell-SDK
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
            $Global:IntuneAuthToken = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $clientid -redirectUri $redirectUri -resourceAppIdURI $resourceUri -UserPrincipalName $UserPrincipalName
            }
    }
    # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
    else {
        $Global:IntuneAuthToken = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $clientid -redirectUri $redirectUri -resourceAppIdURI $resourceUri -UserPrincipalName $UserPrincipalName
    }
    $Global:IntuneAuthToken
}

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
    if([string]::IsNullOrEmpty($UserPrincipalName))
    {
        $UserPrincipalName = Get-CurrentUPN
    }
    
    $resourceUri = "https://outlook.office365.com"
    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    $clientid = "a0c73c16-a7e3-4564-9a95-2bdf47383716"

    $Result = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $clientid -redirectUri $redirectUri -resourceAppIdURI $resourceUri -UserPrincipalName $UserPrincipalName

    $Authorization =  $Result.Authorization
    $Password = ConvertTo-SecureString -AsPlainText $Authorization -Force
    $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $UserPrincipalName, $Password
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/PowerShell-LiveId?BasicAuthToOAuthConversion=true -Credential $Ctoken -Authentication Basic -AllowRedirection
    Import-PSSession $Session
}

#### Call Function ####
### Manage Office
# Only Support App connection (As of : 2019-05)
#https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-service-communications-api-reference
#Exemple : Invoke-O365ServiceCommunications -TenantName $tenantdomain -Operation CurrentStatus -ClientID $ClientID -ClientSecret $ClientSecret | Select-Object WorkloadDisplayName,Status,ID,StatusDisplayName
Function Invoke-O365ServiceCommunications{
    [CmdletBinding(DefaultParameterSetName='ClientSecret')]
    Param(
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [String]
        $TenantName,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [String]
        $Operation,
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
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
        [String]
        $APIVersion = "v1.0"
        
    )
    #https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference
    #https://docs.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis

    $ResourceURI = "https://manage.office.com"
    switch ( $PsCmdlet.ParameterSetName ) 
    {
        "ClientSecret"
        {
            $ManagementHeader = Get-OAuthHeaderAppClientSecretNoDLL -TenantName $TenantName -clientId $ClientID -ClientSecret $ClientSecret -resourceURI $ResourceURI
        }
        "ClientCert"
        {
            $ManagementHeader = Get-OAuthHeaderAppCert -ClientID $ClientID -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword -TenantName $TenantName -resourceURI $ResourceURI
        }
    }
    $TenantName = Validate-TenantName -TenantName $TenantName
    $uri = "https://manage.office.com/api/$($APIVersion)/$TenantGUID/ServiceComms/$($operation)"
    $Query = (Invoke-RestMethod -Uri $uri –Headers $ManagementHeader –Method Get –Verbose).value
    Return $Query
}

#Generic Graph API Call
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
      	[string]$UserPrincipalName
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
                $TokenExpires = ($Global:CSGraphHeader.ExpiresOn.datetime - $DateTime).Minutes
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
        $GraphResponse = Invoke-RestMethod -Uri $GraphURL -Headers $GraphHeader -Method Get
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

### Report
# Based on https://www.altitude365.com/2018/09/23/retrieve-and-analyze-office-365-usage-data-with-powershell-and-microsoft-graph-api/
function Get-UsageReportData {
    param (
    [parameter(Mandatory = $true)]
    [string]$ClientID,
   
   [parameter(Mandatory = $true)]
    [string]$ClientSecret,
   
   [parameter(Mandatory = $true)]
    [string]$TenantName,
    
    [parameter(Mandatory=$false)]
    $Query = "getEmailActivityUserDetail(period='D180')"
    )
   try {
    # Call Microsoft Graph and extract CSV content and convert data to PowerShell objects.
        $UsageData = (Invoke-GraphApi -TenantName $TenantName -Resource reports -QueryParams $Query -ClientID $ClientID -ClientSecret $ClientSecret)| ConvertFrom-Csv
    }
    catch {
        $null
    }
    Return $UsageData
}

### Security
function Get-GraphSecurityData {
    [CmdletBinding(DefaultParameterSetName='UPN')]
    param (
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [Parameter(ParameterSetName='UPN', Mandatory=$True)]
        [String]
        $TenantName,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$false)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$false)]
        [Parameter(ParameterSetName='UPN', Mandatory=$false)]
        [String]
        $Query = "secureScores",
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
        [Parameter(ParameterSetName='UPN', Mandatory=$true)]
      	[string]$redirectUri,
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
      	[string]$UserPrincipalName
    )
    try {
    # Call Microsoft Graph and extract CSV content and convert data to PowerShell objects.
        switch ( $PsCmdlet.ParameterSetName )
        {
            "UPN"
            {
                if([string]::IsNullOrEmpty($UserPrincipalName))
                {
                    $UserPrincipalName = Get-CurrentUPN
                }
                $SecurityData = (Invoke-GraphApi -TenantName $TenantName -Resource security -QueryParams $Query -ClientID $ClientID -UserPrincipalName $UserPrincipalName -redirectUri $redirectUri)
            }
            "ClientSecret"
            {
                $SecurityData = (Invoke-GraphApi -TenantName $TenantName -Resource security -QueryParams $Query -ClientID $ClientID -ClientSecret $ClientSecret)
            }
            "ClientCert"
            {
                $SecurityData = (Invoke-GraphApi -TenantName $TenantName -Resource security -QueryParams $Query -ClientID $ClientID -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword)
            }
        }
    }
    catch {
        $null
    }
    Return $SecurityData
}

### Mail

### Intune Call
#https://github.com/Microsoft/Intune-PowerShell-SDK

