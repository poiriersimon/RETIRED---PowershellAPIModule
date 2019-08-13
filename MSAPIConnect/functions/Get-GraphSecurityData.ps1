<#
.SYNOPSIS
Send Query to the Microsofrt Graph Security API

.DESCRIPTION
Send Query to the Microsofrt Graph Security API with your UPN or Azure AD Application

.PARAMETER TenantName
For Azure AD Application Authentication, you need to specify the Tenant Name, Tenant ID or Registered Domain name on your Azure or Office 365 Tenant

.PARAMETER Query
Optional, Additionnal Graph URL to pass to https://graph.microsoft.com/V1.0/security like "alerts", if no value securescores are used
Currently, there no validation, so refer to the docs.microsoft.com API
#TODO - add url for docs

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
Return the Secure Scores for the Tenant
Get-GraphSecurityData -UserPrincipalName admin@contoso.com -ClientID $ClientIDUPN -redirectUri http://localhost

.NOTES
#
#>

function Get-GraphSecurityData {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingUsernameAndPasswordParams", "")]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "")]
    [CmdletBinding(DefaultParameterSetName='UPN')]
    param (
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$True)]
        [Parameter(ParameterSetName='ClientCert', Mandatory=$True)]
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
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
        [ValidateSet(
            'V1.0',
            'beta'
        )]
        $APIVersion = "v1.0",
        [Parameter(ParameterSetName='ClientCert', Mandatory=$false)]
        [Parameter(ParameterSetName='ClientSecret', Mandatory=$false)]
        [Parameter(ParameterSetName='UPN', Mandatory=$true)]
      	[string]$RedirectUri,
        [Parameter(ParameterSetName='UPN', Mandatory=$False)]
      	[string]$UserPrincipalName
    )
    try {
    # Call Microsoft Graph
        switch ( $PsCmdlet.ParameterSetName )
        {
            "UPN"
            {
                if([string]::IsNullOrEmpty($UserPrincipalName))
                {
                    $UserPrincipalName = Get-CurrentUPN
                }
                $SecurityData = (Invoke-GraphApi -Resource security -QueryParams $Query -ClientID $ClientID -UserPrincipalName $UserPrincipalName -redirectUri $redirectUri)
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
