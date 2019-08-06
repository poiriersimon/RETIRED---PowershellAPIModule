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
                    Write-PSFMessage -Level Host -Message "Authentication need to be refresh" -ForegroundColor Yellow
                    $Global:UPNGraphHeader = Get-OAuthHeaderUPN -clientId $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceURI -UserPrincipalName $UserPrincipalName
                }
            }
            # Authentication doesn't exist, calling Get-GraphAuthHeaderBasedOnUPN function
            else {
                $Global:UPNGraphHeader = Get-OAuthHeaderUPN -clientId $ClientID -redirectUri $redirectUri -resourceAppIdURI $resourceURI -UserPrincipalName $UserPrincipalName
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
                    Write-PSFMessage -Level Host -Message "Authentication need to be refresh" -ForegroundColor Yellow
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
                    Write-PSFMessage -Level Host -Message "Authentication need to be refresh" -ForegroundColor Yellow
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
