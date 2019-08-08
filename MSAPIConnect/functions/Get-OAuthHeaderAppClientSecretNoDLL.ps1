<#
.SYNOPSIS
Authenticate to Azure AD with Azure Directory Authentication Librairy for an Azure Ad Application leveraging Client Secret Authentication

.DESCRIPTION
Authenticate to Azure AD with Azure Directory Authentication Librairy for an Azure Ad Application leveraging Client Secret Authentication

.PARAMETER ClientID
This is the Client ID (Application ID) of the registered Azure AD Application.
The Application need to have the right permission in your tenant.

.PARAMETER ClientSecret
If you are leveraging an Azure AD Application with Client Secret authentication, you need to provide the Secret here

.PARAMETER TenantName
You need to specify the Tenant Name, Tenant ID or Registered Domain name on your Azure or Office 365 Tenant

.PARAMETER ResourceURI
Resource URI of the Azure AD Application that is registered.

.EXAMPLE
TODO - Example
TODO - Line 2

.NOTES
Based on https://www.altitude365.com/2018/09/23/retrieve-and-analyze-office-365-usage-data-with-powershell-and-microsoft-graph-api/

#>

function Get-OAuthHeaderAppClientSecretNoDLL
{
    [OutputType([Hashtable])]
    [cmdletbinding()]
	param(
    [Parameter(Mandatory = $True)]
      	[string]$TenantName ,
    [Parameter(Mandatory = $True)]
        [string]$ClientID,
    [Parameter(Mandatory = $True)]
      	[string]$ClientSecret,
    [Parameter(Mandatory = $True)]
      	[string]$ResourceURI
    
    )
    
    $TenantName = Test-TenantName -TenantName $TenantName

    #Login Endpoint info
    $loginURL = ($(Get-TenantLoginEndPoint -TenantName $TenantName)).token_endpoint

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
