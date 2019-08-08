<#
.SYNOPSIS
Send request to Microsoft Graph API and get Access Token

.DESCRIPTION
Send request to Microsoft Graph API and get Access Token
Can be leveraged against multiple Graph API by specifying the right Resource

.PARAMETER TenantName
For Azure AD Application Authentication, you need to specify the Tenant Name, Tenant ID or Registered Domain name on your Azure or Office 365 Tenant

.PARAMETER Resource
The API ressource to which the request will be sent

.PARAMETER QueryParams
Additionnal Graph URL to pass to Resource like "alerts"
Currently, there no validation, so refer to the API docs

.PARAMETER Body
Optional, Body content to send with the request

.PARAMETER Method
Optional, Default is GET
Valide Value Delete, Get, Head, Merge, Options, Patch, Post, Put, Trace

.PARAMETER ClientID
This is the Client ID (Application ID) of the registered Azure AD Application.
The Application need to have the right permission in your tenant.
#TODO = Document the minimal app permission

.PARAMETER ClientSecret
If you are leveraging an Azure AD Application with Client Secret authentication, you need to provide the Secret here

.PARAMETER CertificatePath
If you are leveraging an Azure AD Application with Certificate authentication, you need to provide the Certificate Path here

.PARAMETER CertificatePassword
If you are leveraging an Azure AD Application with Certificate authentication, you need to provide the Certificate Password here to access the private key

.PARAMETER APIVersion
Optional, default is V1.0
Specify the API version to which send the request.
V1.0 or Beta are the current accepted Value

.PARAMETER RedirectUri
Mandatory for UserPrincipalName Authentication, Optional for Azure AD Application Authentication
Redirect URI of the Azure AD Application that is registered.

.PARAMETER UserPrincipalName
UserPrincipalName of the Admin Account

.EXAMPLE
Get the Details Email Activities for the last 180 days
Invoke-GraphApi -TenantName contoso.com -Resource reports -QueryParams "getEmailActivityUserDetail(period='D180')" -ClientID $ClientID -ClientSecret $ClientSecret

.NOTES
#
#>

Function Invoke-GraphApi
{
    [CmdletBinding(DefaultParameterSetName='UPN')]
    Param(
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [String]
        $TenantName,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [Parameter(ParameterSetName='UPN', Mandatory=$True)]
        [String]
        $Resource,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$False)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$False)]
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
        [String]
        $QueryParams,
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$False)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$False)]
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
        [String]
        $Body,
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
        [ValidateSet(
            'V1.0',
            'beta'
        )]
        $APIVersion = "v1.0",
        [Parameter(ParameterSetName='ClientCert', Mandatory=$false)]
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$false)]
        [Parameter(ParameterSetName='UPN', Mandatory=$True)]
      	[string]$RedirectUri,
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
        [string]
        $UserPrincipalName
    )
    $resourceURI = "https://graph.microsoft.com"
    switch ( $PsCmdlet.ParameterSetName )
    {
        "UPN"
        {
            if($Script:UPNGraphHeader){
                # Setting DateTime to Universal time to work in all timezones
                $DateTime = (Get-Date).ToUniversalTime()

                # If the authToken exists checking when it expires
                $TokenExpires = ($Script:UPNGraphHeader.ExpiresOn.datetime - $DateTime).Minutes
                $UPNMismatch = $UserPrincipalName -ne $Script:UPNGraphHeader.UserID
                $AppIDMismatch = $ClientID -ne $Script:UPNGraphHeader.AppID
                if($TokenExpires -le 0 -or $UPNMismatch -or $AppIDMismatch){
                    Write-PSFMessage -Level Host -Message "Authentication need to be refresh"
                    $Script:UPNGraphHeader = Get-OAuthHeaderUPN -clientId $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceURI -UserPrincipalName $UserPrincipalName
                }
            }
            # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
            else {
                $Script:UPNGraphHeader = Get-OAuthHeaderUPN -clientId $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceURI -UserPrincipalName $UserPrincipalName
            }
            $GraphHeader = $Script:UPNGraphHeader
        }
        "ClientSecret"
        {
            if($Script:CSGraphHeader){
                # Setting DateTime to Universal time to work in all timezones
                $DateTime = (Get-Date).ToUniversalTime()

                # If the authToken exists checking when it expires
                $TokenExpires = ((Get-date ($Script:CSGraphHeader.ExpiresOn)) - $DateTime).Minutes
                $AppIDMismatch = $ClientID -ne $Script:CSGraphHeader.AppID
                if($TokenExpires -le 0 -or $AppIDMismatch){
                    Write-PSFMessage -Level Host -Message "Authentication need to be refresh"
                $Script:CSGraphHeader = Get-OAuthHeaderAppClientSecretNoDLL -TenantName $TenantName -clientId $ClientID -ClientSecret $ClientSecret -resourceURI $ResourceURI
                }
            }
            # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
            else {
                $Script:CSGraphHeader = Get-OAuthHeaderAppClientSecretNoDLL -TenantName $TenantName -clientId $ClientID -ClientSecret $ClientSecret -resourceURI $ResourceURI
            }
            $GraphHeader = $Script:CSGraphHeader
        }
        "ClientCert"
        {
            if($Script:CCGraphHeader){
                # Setting DateTime to Universal time to work in all timezones
                $DateTime = (Get-Date).ToUniversalTime()

                # If the authToken exists checking when it expires
                $TokenExpires = ($Script:CCGraphHeader.ExpiresOn.datetime - $DateTime).Minutes
                $AppIDMismatch = $ClientID -ne $Script:CCGraphHeader.AppID
                if($TokenExpires -le 0 -or $AppIDMismatch){
                    Write-PSFMessage -Level Host -Message "Authentication need to be refresh"
                    $Script:CCGraphHeader = Get-OAuthHeaderAppCert -ClientID $ClientID -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword -TenantName $TenantName -resourceURI $ResourceURI
                }
            }
            # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
            else {
                $Script:CCGraphHeader = Get-OAuthHeaderAppCert -ClientID $ClientID -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword -TenantName $TenantName -resourceURI $ResourceURI
            }
            $GraphHeader = $Script:CCGraphHeader
        }
    }

    #Allow larger data set with multiple read.
    #From :https://smsagent.blog/2018/10/22/querying-for-devices-in-azure-ad-and-intune-with-powershell-and-microsoft-graph/
    try {
        if (([string]::IsNullOrEmpty($QueryParams))) {
            $GraphURL = "https://graph.microsoft.com/$($APIVersion)/$($Resource)"
        }
        else{
            $GraphURL = "https://graph.microsoft.com/$($APIVersion)/$($Resource)/$($QueryParams)"
        }
        if([string]::IsNullOrEmpty($Body)){
            $GraphResponse = Invoke-RestMethod -Uri $GraphURL -Headers $GraphHeader -Method $Method
        }
        else {
            $GraphResponse = Invoke-RestMethod -Uri $GraphURL -Headers $GraphHeader -Method $Method -Body $Body
        }

    }
    catch {
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-PSFMessage -Level Host -Message "Response content:`n$responseBody" -f Red
        Throw "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        Write-PSFMessage -Level Host -Message
        break

        }

    # Return the data
    if($NULL -eq $GraphResponse.Value){
        $Items = $GraphResponse
    }else{
        $Items = $GraphResponse.Value
    }
    $NextLink = $GraphResponse.'@odata.nextLink'
    # Need to loop the requests because only 100 results are returned each time
    While ($NULL -ne $NextLink)
    {
        $GraphResponse = Invoke-RestMethod -Uri $NextLink -Headers $GraphtHeader -Method Get
        $NextLink = $GraphResponse.'@odata.nextLink'
        $Items += $GraphResponse.Value
    }
    Return $Items
}
