<#
.SYNOPSIS
Send Query to the Office 365 Service Communication API

.DESCRIPTION
Send Query to the Office 365 Service Communication API with Azure AD Application

.PARAMETER TenantName
You need to specify the Tenant Name, Tenant ID or Registered Domain name on your Azure or Office 365 Tenant

.PARAMETER Operation
Type of operation to send to the API
For more info see https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference

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

.EXAMPLE
Get current Status of all O365 Services
Invoke-O365ServiceCommunications -TenantName contoso.com -Operation CurrentStatus -ClientID $ClientID -ClientSecret $ClientSecret

.NOTES
Only Support App connection (As of : 2019-05)
https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-service-communications-api-reference
https://docs.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference
https://docs.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis

#>

Function Invoke-O365ServiceCommunication
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
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
        [ValidateSet(
            'V1.0',
            'beta'
        )]
        $APIVersion = "v1.0"

    )

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
