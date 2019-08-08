<#
.SYNOPSIS
Authenticate to Azure AD with Azure Directory Authentication Librairy with your UserPrincipalName

.DESCRIPTION
Authenticate to Azure AD with Azure Directory Authentication Librairy with your UserPrincipalName and and Azure Ad Application

.PARAMETER ClientID
This is the Client ID (Application ID) of the registered Azure AD Application.
The Application need to have the right permission in your tenant.

.PARAMETER RedirectUri
Redirect URI of the Azure AD Application that is registered.

.PARAMETER ResourceAppIdURI
Resource URI of the Azure AD Application that is registered.

.PARAMETER UserPrincipalName
UserPrincipalName of the Admin Account

.EXAMPLE
TODO - Example
TODO - Line 2

.NOTES
#
#>

function Get-OAuthHeaderUPN
{
    [OutputType([Hashtable])]
    [cmdletbinding()]
	param(
    [Parameter(Mandatory = $True)]
      	[string]$ClientID,
    [Parameter(Mandatory = $True)]
      	[string]$RedirectUri,
    [Parameter(Mandatory = $True)]
      	[string]$ResourceAppIdURI,
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
    $NULL = [System.Reflection.Assembly]::LoadFrom($AzureADDLL)

    [string] $authority = $TenantInfo.authorization_endpoint
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
