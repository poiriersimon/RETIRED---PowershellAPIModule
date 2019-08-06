Function Connect-Intune{
    [CmdletBinding()]
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
    ##Only Support User Connection no Application Connect (As Of : 2019-05)
    [string]$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
    [string]$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
    [string]$resourceUri = "https://graph.microsoft.com"

    if($Global:IntuneAuthToken){
        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($Global:IntuneAuthToken.ExpiresOn.datetime - $DateTime).Minutes

            if($TokenExpires -le 0){

            Write-PSFMessage -Level Host -Message "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
            $Global:IntuneAuthToken = Get-OAuthHeaderUPN -clientId $clientid -redirectUri $redirectUri -resourceAppIdURI $resourceUri -UserPrincipalName $UserPrincipalName
            }
    }
    # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
    else {
        $Global:IntuneAuthToken = Get-OAuthHeaderUPN -clientId $clientid -redirectUri $redirectUri -resourceAppIdURI $resourceUri -UserPrincipalName $UserPrincipalName
    }
    $Global:IntuneAuthToken
}
