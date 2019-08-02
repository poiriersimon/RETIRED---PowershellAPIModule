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
    $ExpireOn = "$(ConvertFromCtime -ctime $oauth.expires_on)"
    $headers = @{
        "Authorization" = "$($oauth.token_type) $($oauth.access_token)"
        "ExpiresOn"     = $ExpireOn
        "AppID"     = $ClientID
    }
    Return $headers
}
