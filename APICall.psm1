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
Powershell module to allow multiple way of send request toward multiple Microsoft API

.DESCRIPTION
This Powershell module can be used to send request to Microsoft Graph API but also other API leveraging Azure AD

.EXAMPLE
Manual API call to get Email Activity
Invoke-GraphApi -TenantName Contoso -Resource reports -QueryParams "getEmailActivityUserDetail(period='D180')" -ClientID $ClientID -ClientSecret $ClientSecret

.EXAMPLE
Get Secure Score
Get-GraphSecurityData -UserPrincipalName admin@contoso.com -TenantName contoso -ClientID $ClientIDUPN -redirectUri http://localhost

.NOTES
Other Module that do part of what is done here even better:
- EXCH-REST: https://github.com/gscales/Exch-Rest
- Intune: https://github.com/Microsoft/Intune-PowerShell-SDK

List of Major Graph Service : https://docs.microsoft.com/en-us/graph/overview-major-services
#>


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
    #For a complete Intune module : https://github.com/Microsoft/Intune-PowerShell-SDK
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

    if($Global:UPNEXOHeader){
        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($Global:UPNEXOHeader.ExpiresOn.datetime - $DateTime).Minutes
        $UPNMismatch = $UserPrincipalName -ne $Global:UPNEXOHeader.UserID
        $AppIDMismatch = $ClientID -ne $Global:UPNEXOHeader.AppID
        if($TokenExpires -le 0 -or $UPNMismatch -or $AppIDMismatch){
            write-host "Authentication need to be refresh" -ForegroundColor Yellow
            $Global:UPNEXOHeader = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceURI -UserPrincipalName $UserPrincipalName
        }
    }
    # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
    else {
        $Global:UPNEXOHeader = Get-OAuthHeaderUPN -TenantName $TenantName -clientId $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceURI -UserPrincipalName $UserPrincipalName
    }
    $Result = $Global:UPNEXOHeader
    
    $Authorization =  $Result.Authorization
    $Password = ConvertTo-SecureString -AsPlainText $Authorization -Force
    $Ctoken = New-Object System.Management.Automation.PSCredential -ArgumentList $UserPrincipalName, $Password
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/PowerShell-LiveId?BasicAuthToOAuthConversion=true -Credential $Ctoken -Authentication Basic -AllowRedirection
    Import-PSSession $Session
}

### Manage Office
# Only Support App connection (As of : 2019-05)
#https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-service-communications-api-reference
#Exemple : Invoke-O365ServiceCommunications -TenantName $tenantdomain -Operation CurrentStatus -ClientID $ClientID -ClientSecret $ClientSecret | Select-Object WorkloadDisplayName,Status,ID,StatusDisplayName
Function Invoke-O365ServiceCommunications 
{
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
    $TenantGUID = (Get-TenantLoginEndPoint $TenantName).token_endpoint.split("/")[-3]
    $uri = "https://manage.office.com/api/$($APIVersion)/$TenantGUID/ServiceComms/$($operation)"
    $Query = (Invoke-RestMethod -Uri $uri -Headers $ManagementHeader -Method Get -Verbose).value
    Return $Query
}

#TODO: Add Start/Stop/List/Get Subscription from the Management API (O365ManagedAPI.ps1)

### Report
# Based on https://www.altitude365.com/2018/09/23/retrieve-and-analyze-office-365-usage-data-with-powershell-and-microsoft-graph-api/
function Get-GraphUsageReportData {
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
        Write-Error "Couldn't complete"
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


#TODO : Add Mail cmdlet
### Mail

#TODO : Add Intune Call Exemple
### Intune Call
#https://github.com/Microsoft/Intune-PowerShell-SDK