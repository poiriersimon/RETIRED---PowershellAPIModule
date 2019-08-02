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
