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
