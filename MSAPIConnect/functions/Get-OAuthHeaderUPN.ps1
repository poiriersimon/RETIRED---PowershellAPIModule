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
